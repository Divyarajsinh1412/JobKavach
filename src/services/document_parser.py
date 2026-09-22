"""
Enterprise Document & Email Parser Service.
Extracts raw text, forensic headers, attachments, and embedded URLs from
.eml, .msg, .pdf, .docx, .txt, .html, and .rtf files using zero-dependency,
defensive, memory-safe parsing.
"""

import email
import email.policy
import email.utils
import hashlib
import html
import io
import logging
import os
import re
import zlib
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from src.config.settings import (
    SUSPICIOUS_ATTACHMENT_EXTENSIONS,
    SUPPORTED_DOC_EXTENSIONS,
)
from src.models.schemas import (
    DocumentAnalysisResult,
    EmailMetadata,
    AttachmentInfo,
)

logger = logging.getLogger("SOC-AUDIT")

# Linear regex for URL extraction
URL_PATTERN = re.compile(r"https?://[^\s<>\"'{}|\\^`]+", re.IGNORECASE)

# Strips HTML tags safely
TAG_RE = re.compile(r"<[^>]+>")
SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)


class DocumentParser:
    """Enterprise parser for extracting text and forensic indicators from diverse files."""

    @classmethod
    def is_supported(cls, filename: str) -> bool:
        """Checks if the file extension is supported."""
        ext = os.path.splitext(filename)[1].lower()
        return ext in SUPPORTED_DOC_EXTENSIONS

    @classmethod
    def parse_file(cls, file_bytes: bytes, filename: str) -> DocumentAnalysisResult:
        """
        Parses arbitrary file bytes according to file extension, returning
        a structured DocumentAnalysisResult.
        """
        ext = os.path.splitext(filename)[1].lower()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        file_size = len(file_bytes)
        warnings: List[str] = []

        extracted_text = ""
        email_meta: Optional[EmailMetadata] = None
        embedded_urls: List[str] = []

        try:
            if ext == ".eml":
                extracted_text, email_meta = cls._parse_eml(file_bytes)
                if email_meta:
                    embedded_urls = email_meta.extracted_urls
            elif ext == ".docx":
                extracted_text = cls._parse_docx(file_bytes)
                embedded_urls = cls._extract_urls(extracted_text)
            elif ext == ".pdf":
                extracted_text, pdf_warn = cls._parse_pdf(file_bytes)
                if pdf_warn:
                    warnings.append(pdf_warn)
                embedded_urls = cls._extract_urls(extracted_text)
            elif ext in (".html", ".htm"):
                raw_html = cls._decode_text(file_bytes)
                embedded_urls = cls._extract_urls(raw_html)
                extracted_text = cls._clean_html(raw_html)
            elif ext == ".rtf":
                extracted_text = cls._parse_rtf(file_bytes)
                embedded_urls = cls._extract_urls(extracted_text)
            elif ext == ".msg":
                extracted_text, email_meta, msg_warn = cls._parse_msg(file_bytes)
                if msg_warn:
                    warnings.append(msg_warn)
                if email_meta:
                    embedded_urls = email_meta.extracted_urls
                else:
                    embedded_urls = cls._extract_urls(extracted_text)
            else:
                # Default plain text / fallback decoder
                extracted_text = cls._decode_text(file_bytes)
                embedded_urls = cls._extract_urls(extracted_text)

        except Exception as err:
            logger.error(f"[DocumentParser] Error parsing '{filename}': {err}", exc_info=True)
            warnings.append(f"Parser error: {str(err)}")
            if not extracted_text:
                extracted_text = cls._decode_text(file_bytes)

        return DocumentAnalysisResult(
            filename=filename,
            file_format=ext.replace(".", "").upper() or "TXT",
            file_size=file_size,
            extracted_text=extracted_text.strip(),
            email_metadata=email_meta,
            embedded_urls=list(set(embedded_urls)),
            sha256_hash=sha256,
            parse_warnings=warnings,
        )

    # ==========================================================================
    # 1. EML / EMAIL PARSER
    # ==========================================================================

    @classmethod
    def _parse_eml(cls, file_bytes: bytes) -> Tuple[str, EmailMetadata]:
        """Parses RFC 822 / MIME .eml bytes into plain text and forensic headers."""
        msg = email.message_from_bytes(file_bytes, policy=email.policy.default)

        # Header Extraction
        sender = str(msg.get("From", "")).strip()
        subject = str(msg.get("Subject", "")).strip()
        date_str = str(msg.get("Date", "")).strip()
        reply_to = str(msg.get("Reply-To", "")).strip()

        # Parse sender domain
        _, sender_addr = email.utils.parseaddr(sender)
        sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

        # Parse reply-to domain
        _, reply_addr = email.utils.parseaddr(reply_to)
        reply_to_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

        # Reply-To Mismatch Detection
        reply_to_mismatch = False
        if reply_to_domain and sender_domain:
            if reply_to_domain != sender_domain:
                reply_to_mismatch = True

        # Check if Reply-To is a free webmail service when sender isn't
        webmail_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"}
        if reply_to_domain in webmail_domains and sender_domain not in webmail_domains and sender_domain:
            reply_to_mismatch = True

        # SPF & DKIM Header Analysis
        spf_status = cls._extract_auth_status(msg, ["Received-SPF", "Authentication-Results"], "spf")
        dkim_status = cls._extract_auth_status(msg, ["Authentication-Results", "DKIM-Signature"], "dkim")

        # Body Text & Attachment Extraction
        body_parts: List[str] = []
        attachments: List[AttachmentInfo] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", "")).lower()
                filename = part.get_filename()

                if filename or "attachment" in content_disposition:
                    # Attachment Detected
                    fname = filename or "unnamed_attachment"
                    fbytes = part.get_payload(decode=True) or b""
                    is_susp = cls._is_suspicious_attachment(fname)
                    reason = "High-risk executable, script, or archive extension" if is_susp else "Standard file"
                    attachments.append(AttachmentInfo(
                        filename=fname,
                        file_type=content_type,
                        size_bytes=len(fbytes),
                        is_suspicious=is_susp,
                        reason=reason
                    ))
                elif content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(cls._decode_text(payload))
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(cls._clean_html(cls._decode_text(payload)))
                    except Exception:
                        pass
        else:
            # Single-part message
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            if payload:
                raw_str = cls._decode_text(payload)
                if content_type == "text/html":
                    body_parts.append(cls._clean_html(raw_str))
                else:
                    body_parts.append(raw_str)

        full_body = "\n\n".join(body_parts) if body_parts else cls._decode_text(file_bytes)
        urls = cls._extract_urls(full_body)

        meta = EmailMetadata(
            sender=sender,
            sender_domain=sender_domain,
            reply_to=reply_to,
            reply_to_domain=reply_to_domain,
            reply_to_mismatch=reply_to_mismatch,
            subject=subject,
            date=date_str,
            spf_status=spf_status,
            dkim_status=dkim_status,
            attachments=attachments,
            extracted_urls=urls,
        )

        # Header summary prepended to offer text for linguistic scanning
        header_summary = f"Subject: {subject}\nFrom: {sender}\nReply-To: {reply_to}\n\n"
        combined_text = header_summary + full_body

        return combined_text, meta

    # ==========================================================================
    # 2. DOCX PARSER (Standard Library zipfile + xml.etree)
    # ==========================================================================

    @classmethod
    def _parse_docx(cls, file_bytes: bytes) -> str:
        """Extracts text paragraphs from Microsoft Word .docx without external dependencies."""
        with io.BytesIO(file_bytes) as docx_stream:
            with zipfile.ZipFile(docx_stream) as zf:
                if "word/document.xml" not in zf.namelist():
                    raise ValueError("Invalid .docx file: 'word/document.xml' missing.")
                xml_content = zf.read("word/document.xml")

        # Parse XML tree
        tree = ET.fromstring(xml_content)
        # Namespace for WordprocessingML
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}

        paragraphs: List[str] = []
        for p in tree.iterfind(".//w:p", ns):
            texts = [node.text for node in p.iterfind(".//w:t", ns) if node.text]
            if texts:
                paragraphs.append("".join(texts))

        return "\n\n".join(paragraphs)

    # ==========================================================================
    # 3. PDF PARSER (Hybrid: pypdf if installed + pure Python stream extractor)
    # ==========================================================================

    @classmethod
    def _parse_pdf(cls, file_bytes: bytes) -> Tuple[str, Optional[str]]:
        """Extracts text from PDF documents using pypdf if available or pure-Python fallback."""
        warning: Optional[str] = None

        # Strategy A: Use pypdf if installed in environment
        try:
            import pypdf  # type: ignore
            reader = pypdf.PdfReader(io.BytesIO(file_bytes))
            pages_text = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    pages_text.append(t)
            if pages_text:
                return "\n\n".join(pages_text), None
        except ImportError:
            pass
        except Exception as e:
            warning = f"pypdf reader warning: {e}"

        # Strategy B: Pure Python FlateDecode Stream Text Extractor
        try:
            text_extracted = cls._extract_pdf_text_streams(file_bytes)
            if text_extracted.strip():
                return text_extracted, warning
        except Exception as e:
            warning = f"PDF stream decompression failed: {e}"

        # Strategy C: Printable ASCII fallback
        ascii_text = cls._extract_printable_ascii(file_bytes)
        return ascii_text, warning or "Parsed using fallback ASCII stream recovery."

    @classmethod
    def _extract_pdf_text_streams(cls, file_bytes: bytes) -> str:
        """Decompresses /FlateDecode streams in PDF and extracts textual strings."""
        stream_regex = re.compile(b"stream[\r\n]+(.*?)[\r\n]+endstream", re.DOTALL)
        extracted_chunks: List[str] = []

        for match in stream_regex.finditer(file_bytes):
            stream_data = match.group(1)
            decompressed: Optional[bytes] = None

            # Try zlib decompression
            try:
                decompressed = zlib.decompress(stream_data)
            except Exception:
                try:
                    decompressed = zlib.decompress(stream_data, -zlib.MAX_WBITS)
                except Exception:
                    decompressed = None

            if decompressed:
                # Look for PDF text operators: (string) Tj or [(array)] TJ
                tj_matches = re.findall(rb"\((.*?)\)\s*Tj", decompressed)
                for tj in tj_matches:
                    try:
                        extracted_chunks.append(tj.decode("latin-1", errors="ignore"))
                    except Exception:
                        pass

                tj_array_matches = re.findall(rb"\[(.*?)\]\s*TJ", decompressed)
                for tj_arr in tj_array_matches:
                    inner_strings = re.findall(rb"\((.*?)\)", tj_arr)
                    words = [s.decode("latin-1", errors="ignore") for s in inner_strings]
                    if words:
                        extracted_chunks.append("".join(words))

        return " ".join(extracted_chunks)

    # ==========================================================================
    # 4. HTML, RTF, AND TEXT HELPERS
    # ==========================================================================

    @classmethod
    def _parse_html(cls, file_bytes: bytes) -> str:
        """Strips tags and decodes HTML entities into clean text."""
        raw_html = cls._decode_text(file_bytes)
        return cls._clean_html(raw_html)

    @classmethod
    def _clean_html(cls, raw_html: str) -> str:
        """Removes script, style, tags, and unescapes entities."""
        no_script = SCRIPT_STYLE_RE.sub(" ", raw_html)
        no_tags = TAG_RE.sub(" ", no_script)
        unescaped = html.unescape(no_tags)
        # Collapse whitespace
        return re.sub(r"\s+", " ", unescaped).strip()

    @classmethod
    def _parse_rtf(cls, file_bytes: bytes) -> str:
        """Extracts plain text from Rich Text Format (.rtf)."""
        text = cls._decode_text(file_bytes)
        # Strip RTF control groups and commands
        clean = re.sub(r"\{\*?\\[^{}]+?\}", "", text)
        clean = re.sub(r"\\[a-zA-Z]+\-?\d* ?", " ", clean)
        clean = re.sub(r"[{}\\]", "", clean)
        return re.sub(r"\s+", " ", clean).strip()

    @classmethod
    def _parse_msg(cls, file_bytes: bytes) -> Tuple[str, Optional[EmailMetadata], Optional[str]]:
        """Handles Outlook .msg files with fallback text recovery."""
        # Check if extract_msg is available
        try:
            import extract_msg  # type: ignore
            msg = extract_msg.Message(io.BytesIO(file_bytes))
            sender = msg.sender or ""
            subject = msg.subject or ""
            date_str = str(msg.date) if msg.date else ""
            body = msg.body or ""
            _, sender_addr = email.utils.parseaddr(sender)
            sender_domain = sender_addr.split("@")[-1].lower() if "@" in sender_addr else ""

            meta = EmailMetadata(
                sender=sender,
                sender_domain=sender_domain,
                subject=subject,
                date=date_str,
                extracted_urls=cls._extract_urls(body),
            )
            return f"Subject: {subject}\nFrom: {sender}\n\n{body}", meta, None
        except ImportError:
            # Fallback: Extract ASCII strings from MSG binary
            raw_text = cls._extract_printable_ascii(file_bytes)
            urls = cls._extract_urls(raw_text)
            return raw_text, None, "Outlook .msg parsed using raw stream text recovery."

    # ==========================================================================
    # 5. FORENSIC HELPER UTILITIES
    # ==========================================================================

    @classmethod
    def _is_suspicious_attachment(cls, filename: str) -> bool:
        """Checks if attachment has a known malicious/phishing extension."""
        ext = os.path.splitext(filename)[1].lower()
        return ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS

    @classmethod
    def _extract_urls(cls, text: str) -> List[str]:
        """Extracts unique HTTP/HTTPS URLs from text."""
        matches = URL_PATTERN.findall(text)
        return list(set(matches))

    @classmethod
    def _extract_auth_status(cls, msg: email.message.EmailMessage, headers: List[str], auth_type: str) -> Optional[str]:
        """Extracts SPF or DKIM validation status (pass, fail, softfail) from headers."""
        for h in headers:
            val = str(msg.get(h, "")).lower()
            if not val:
                continue
            if f"{auth_type}=pass" in val or "pass" in val:
                return "PASS"
            if f"{auth_type}=fail" in val or "fail" in val:
                return "FAIL"
            if f"{auth_type}=softfail" in val or "softfail" in val:
                return "SOFTFAIL"
        return None

    @classmethod
    def _decode_text(cls, data: bytes) -> str:
        """Decodes raw bytes attempting common encodings."""
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252", "utf-16"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return data.decode("utf-8", errors="replace")

    @classmethod
    def _extract_printable_ascii(cls, data: bytes) -> str:
        """Extracts contiguous printable ASCII strings from binary payloads."""
        result = []
        current = []
        for b in data:
            if 32 <= b <= 126 or b in (10, 13):
                current.append(chr(b))
            else:
                if len(current) >= 4:
                    result.append("".join(current))
                current = []
        if len(current) >= 4:
            result.append("".join(current))
        return "\n".join(result)
