"""
Domain Verification Engine (DNS & WHOIS Enumeration).
Extracts domain registration age, detects WHOIS privacy shielding,
and provides comprehensive exception handling against network/firewall failures.
"""

import re
import socket
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, Any

from src.config.settings import PRIVACY_SIGNATURES, DOMAIN_AGE_THRESHOLD_DAYS
from src.models.schemas import DomainAnalysisResult

# Optional WHOIS import with enterprise-grade fallback
try:
    import whois
    WHOIS_AVAILABLE = True
    try:
        from whois.parser import PywhoisError
    except (ImportError, AttributeError):
        try:
            from whois import WhoisError as PywhoisError
        except (ImportError, AttributeError):
            class PywhoisError(Exception):
                pass
except ImportError:
    WHOIS_AVAILABLE = False
    class PywhoisError(Exception):
        pass

logger = logging.getLogger("PhishingInspector.DomainVerifier")


class DomainVerifier:
    """
    Performs DNS & WHOIS analysis, extracting domain age and privacy shielding.

    DNS & WHOIS EXCEPTION HANDLING LOGIC:
    -------------------------------------
    Enterprise environments frequently encounter network firewalls, rate-limits,
    or blocked port 43 connections. To guarantee resiliency:
    1. Input Normalization: URLs, email addresses, and raw hostnames are cleanly parsed
       via urllib.parse.urlparse and regex validation before any network request.
    2. WHOIS Socket Timeouts: whois.whois calls are bounded by standard socket timeout limits.
    3. Specific Exception Trapping:
       - whois.parser.PywhoisError: Handled when a domain is non-existent, unregistered,
         or unparseable by the TLD parser.
       - socket.timeout / TimeoutError: Trapped when outbound port 43 is firewalled or throttled.
       - ConnectionResetError / socket.gaierror: Network unreachable / DNS failure.
       - Generic Exception: Trapped cleanly without crashing the UI, returning an informative
         telemetry state and fallback flags.
    4. Masked WHOIS Detection: Evaluates 'org', 'registrant_name', and 'registrar' fields
       against a signature database of known privacy proxy services (Domains By Proxy,
       WhoisGuard, Withheld for Privacy, PrivacyProtect, etc.).
    """

    def __init__(self):
        self.privacy_signatures = PRIVACY_SIGNATURES
        self.age_threshold = DOMAIN_AGE_THRESHOLD_DAYS

    @staticmethod
    def extract_domain(raw_input: str) -> Optional[str]:
        """
        Sanitizes and extracts the bare domain from raw URLs, hostnames, or emails.
        Example: 'hr@careers-google.com' -> 'careers-google.com'
        """
        if not raw_input or not raw_input.strip():
            return None
        cleaned = raw_input.strip()

        # Handle email format
        if "@" in cleaned:
            parts = cleaned.split("@")
            cleaned = parts[-1].strip()

        # Handle URL schemes
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "http://" + cleaned

        try:
            parsed = urlparse(cleaned)
            hostname = parsed.netloc or parsed.path
            # Strip ports, paths, credentials
            hostname = hostname.split(":")[0].strip()
            # Basic FQDN validation regex
            if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", hostname):
                return hostname.lower()
            return None
        except Exception:
            return None

    def verify_domain(self, domain_input: str) -> DomainAnalysisResult:
        """
        Queries WHOIS records and computes domain age and privacy indicators.
        Provides comprehensive exception handling for PywhoisError, timeouts, and connection resets.
        """
        domain = self.extract_domain(domain_input)
        if not domain:
            return DomainAnalysisResult(
                domain=domain_input,
                is_valid_format=False,
                error_message="Invalid domain or URL format provided."
            )

        if not WHOIS_AVAILABLE:
            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=False,
                error_message="python-whois module is not installed. WHOIS lookup disabled."
            )

        try:
            logger.info(f"Querying WHOIS for target domain: {domain}")
            # Execute WHOIS query
            record = whois.whois(domain)

            # Extract creation date (WHOIS data can return datetime or list of datetimes)
            creation_date_raw = record.get("creation_date")
            creation_date = None
            if isinstance(creation_date_raw, list):
                # Use earliest creation date if list
                valid_dates = [d for d in creation_date_raw if isinstance(d, datetime)]
                creation_date = min(valid_dates) if valid_dates else None
            elif isinstance(creation_date_raw, datetime):
                creation_date = creation_date_raw

            domain_age_days = None
            is_new_domain = False
            if creation_date:
                # Ensure UTC offset awareness
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
                delta = now_utc - creation_date
                domain_age_days = max(0, delta.days)
                # Requirement: < 180 days domain age
                if domain_age_days < self.age_threshold:
                    is_new_domain = True

            # Extract registrar and registrant info
            registrar = record.get("registrar")
            if isinstance(registrar, list):
                registrar = ", ".join(str(r) for r in registrar)

            registrant_org = record.get("org") or record.get("registrant_name")
            if isinstance(registrant_org, list):
                registrant_org = ", ".join(str(o) for o in registrant_org)

            # Detect WHOIS Privacy Shield / Masking
            is_masked = self._detect_privacy_shield(record)

            raw_summary = {
                "registrar": registrar or "Unknown",
                "creation_date": creation_date.strftime("%Y-%m-%d %H:%M:%S UTC") if creation_date else "Unknown",
                "expiration_date": str(record.get("expiration_date", "Unknown")),
                "status": record.get("status", "Unknown"),
                "org": registrant_org or "Unknown"
            }

            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=True,
                creation_date=creation_date,
                domain_age_days=domain_age_days,
                is_new_domain=is_new_domain,
                is_masked=is_masked,
                registrar=str(registrar) if registrar else None,
                registrant_org=str(registrant_org) if registrant_org else None,
                raw_summary=raw_summary
            )

        except PywhoisError as exc:
            # Trapping WHOIS parser errors (unregistered or unparseable TLD)
            err_msg = f"WHOIS Parser Error: {str(exc)}"
            logger.warning(f"Domain lookup exception for {domain}: {err_msg}")
            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=False,
                error_message=err_msg
            )
        except (socket.timeout, TimeoutError) as exc:
            # Trapping WHOIS socket timeouts
            err_msg = f"WHOIS Socket Timeout: Connection timed out querying port 43 - {str(exc)}"
            logger.warning(f"Domain lookup exception for {domain}: {err_msg}")
            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=False,
                error_message=err_msg
            )
        except (ConnectionResetError, socket.gaierror) as exc:
            # Trapping network connection resets and DNS resolution failures
            err_msg = f"WHOIS Connection Error: Network reset or DNS failure - {str(exc)}"
            logger.warning(f"Domain lookup exception for {domain}: {err_msg}")
            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=False,
                error_message=err_msg
            )
        except Exception as exc:
            # Generic catch-all to prevent unhandled crashes
            err_msg = f"WHOIS Query Failed: {type(exc).__name__} - {str(exc)}"
            logger.warning(f"Domain lookup exception for {domain}: {err_msg}")
            return DomainAnalysisResult(
                domain=domain,
                is_valid_format=True,
                lookup_successful=False,
                error_message=err_msg
            )

    def _detect_privacy_shield(self, record: Any) -> bool:
        """Inspects WHOIS records for known privacy proxy shields."""
        search_fields = [
            str(record.get("org", "")).lower(),
            str(record.get("registrant_name", "")).lower(),
            str(record.get("registrar", "")).lower(),
            str(record.get("emails", "")).lower()
        ]
        combined = " ".join(search_fields)
        return any(sig in combined for sig in self.privacy_signatures)
