"""
Comprehensive Unit Tests for Document & Email Parser Service and XAI Integration.
Validates RFC 822 .eml parsing, .docx XML extraction, .html text stripping,
Reply-To mismatch detection, attachment risk analysis, and XAI feature attributions.
"""

import io
import unittest
import zipfile

from src.models.schemas import (
    TextAnalysisResult,
    DomainAnalysisResult,
    DocumentAnalysisResult,
    EmailMetadata,
    AttachmentInfo,
)
from src.services.document_parser import DocumentParser
from src.services.scoring_engine import ThreatScoringEngine
from src.services.xai_engine import ExplainabilityEngine


class TestDocumentParser(unittest.TestCase):
    """Test suite for DocumentParser service."""

    def test_eml_parsing_with_reply_to_mismatch(self):
        """Validates that an RFC 822 .eml file extracts headers and detects Reply-To redirection."""
        eml_content = (
            b"From: Apple Careers <recruiter@apple.com>\r\n"
            b"To: Jordan Smith <jordan@example.com>\r\n"
            b"Reply-To: scammer_recruiter@gmail.com\r\n"
            b"Subject: URGENT: Job Offer Confirmation\r\n"
            b"Date: Mon, 22 Sep 2026 10:00:00 +0000\r\n"
            b"Received-SPF: Pass\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Congratulations! You have been selected for employment.\r\n"
            b"Please visit https://apple-careers-portal.xyz to complete onboarding."
        )

        result = DocumentParser.parse_file(eml_content, "offer_letter.eml")

        self.assertEqual(result.file_format, "EML")
        self.assertIsNotNone(result.email_metadata)
        self.assertEqual(result.email_metadata.sender_domain, "apple.com")
        self.assertEqual(result.email_metadata.reply_to_domain, "gmail.com")
        self.assertTrue(result.email_metadata.reply_to_mismatch)
        self.assertEqual(result.email_metadata.subject, "URGENT: Job Offer Confirmation")
        self.assertIn("https://apple-careers-portal.xyz", result.embedded_urls)
        self.assertIn("Congratulations!", result.extracted_text)

    def test_eml_parsing_with_suspicious_attachment(self):
        """Validates that .eml parser flags executable and high-risk attachments."""
        multipart_eml = (
            b"From: HR Department <hr@corp.com>\r\n"
            b"Subject: Employment Agreement\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="BOUNDARY"\r\n'
            b"\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Please run the attached onboarding software.\r\n"
            b"\r\n"
            b"--BOUNDARY\r\n"
            b"Content-Type: application/x-msdownload\r\n"
            b'Content-Disposition: attachment; filename="onboarding_setup.exe"\r\n'
            b"\r\n"
            b"MZ_FAKE_EXECUTABLE_CONTENT\r\n"
            b"--BOUNDARY--"
        )

        result = DocumentParser.parse_file(multipart_eml, "agreement.eml")
        self.assertIsNotNone(result.email_metadata)
        self.assertEqual(len(result.email_metadata.attachments), 1)
        att = result.email_metadata.attachments[0]
        self.assertEqual(att.filename, "onboarding_setup.exe")
        self.assertTrue(att.is_suspicious)

    def test_docx_parsing(self):
        """Validates that a valid in-memory .docx archive extracts XML paragraphs."""
        docx_buffer = io.BytesIO()
        with zipfile.ZipFile(docx_buffer, "w") as zf:
            document_xml = (
                b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:body>'
                b'<w:p><w:r><w:t>Official Employment Contract</w:t></w:r></w:p>'
                b'<w:p><w:r><w:t>Starting base salary is $120,000.</w:t></w:r></w:p>'
                b'</w:body>'
                b'</w:document>'
            )
            zf.writestr("word/document.xml", document_xml)

        result = DocumentParser.parse_file(docx_buffer.getvalue(), "contract.docx")
        self.assertEqual(result.file_format, "DOCX")
        self.assertIn("Official Employment Contract", result.extracted_text)
        self.assertIn("Starting base salary is $120,000.", result.extracted_text)

    def test_html_parsing(self):
        """Validates that HTML files strip tags, unescape entities, and extract hyperlinks."""
        html_content = (
            b"<html><head><style>body { color: red; }</style></head>"
            b"<body><h1>Job Offer</h1><p>Send funds via <a href='https://pay.example.com'>Portal</a> &amp; proceed.</p></body></html>"
        )
        result = DocumentParser.parse_file(html_content, "letter.html")
        self.assertEqual(result.file_format, "HTML")
        self.assertNotIn("<style>", result.extracted_text)
        self.assertNotIn("<h1>", result.extracted_text)
        self.assertIn("Job Offer Send funds via Portal & proceed.", result.extracted_text)
        self.assertIn("https://pay.example.com", result.embedded_urls)

    def test_scoring_with_document_indicators(self):
        """Validates that ThreatScoringEngine incorporates Reply-To mismatch and suspicious attachments."""
        text_res = TextAnalysisResult()
        email_meta = EmailMetadata(
            sender="hr@company.com",
            reply_to="attacker@gmail.com",
            reply_to_mismatch=True,
            attachments=[
                AttachmentInfo(
                    filename="setup.exe",
                    file_type="application/octet-stream",
                    size_bytes=1024,
                    is_suspicious=True,
                    reason="Executable"
                )
            ]
        )
        doc_res = DocumentAnalysisResult(
            filename="letter.eml",
            file_format="EML",
            email_metadata=email_meta
        )

        evaluation = ThreatScoringEngine.evaluate(text_res, domain_result=None, doc_result=doc_res)

        # Reply-To mismatch (+25%) + Suspicious attachment (+20%) = 45%
        self.assertEqual(evaluation.score, 45.0)
        self.assertEqual(evaluation.risk_level, "SUSPICIOUS")
        factors = [f["factor"] for f in evaluation.score_breakdown]
        self.assertIn("Email Reply-To Mismatch / Webmail Redirection", factors)
        self.assertIn("Suspicious Executable / Archive Attachment", factors)

    def test_xai_explainability_with_document(self):
        """Validates that ExplainabilityEngine computes attributions and highlights for document IoCs."""
        text_res = TextAnalysisResult()
        email_meta = EmailMetadata(
            sender="hr@legitcorp.com",
            reply_to="fraudster@yahoo.com",
            reply_to_mismatch=True,
            attachments=[
                AttachmentInfo(
                    filename="trojan.bat",
                    file_type="application/x-bat",
                    size_bytes=512,
                    is_suspicious=True,
                    reason="Script"
                )
            ]
        )
        doc_res = DocumentAnalysisResult(
            filename="phish.eml",
            file_format="EML",
            email_metadata=email_meta
        )

        evaluation = ThreatScoringEngine.evaluate(text_res, domain_result=None, doc_result=doc_res)
        raw_text = "From: hr@legitcorp.com\nReply-To: fraudster@yahoo.com\nPlease run trojan.bat"

        xai = ExplainabilityEngine.explain(
            threat_evaluation=evaluation,
            text_result=text_res,
            domain_result=None,
            raw_text=raw_text,
            doc_result=doc_res
        )

        # Check attributions
        attr_names = [a.feature_name for a in xai.attributions]
        self.assertIn("Email Reply-To Mismatch", attr_names)
        self.assertIn("Suspicious Attachment Payload", attr_names)

        # Check HTML highlighting contains xai-mark for the mismatch
        self.assertIn("fraudster@yahoo.com", xai.highlighted_html)
        self.assertIn("xai-mark", xai.highlighted_html)


if __name__ == "__main__":
    unittest.main()
