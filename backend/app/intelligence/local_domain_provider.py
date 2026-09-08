"""Default DomainIntelligenceProvider: local DNS (MX/NS) + python-whois + Spamhaus DBL
domain-reputation check. No API key needed. Every external call is timeout-protected
and degrades to available=False/unavailable_reason rather than raising — a WHOIS
failure or an unsupported TLD must never block the rest of the ingestion pipeline."""

import socket
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import whois as python_whois

from app.intelligence.base import DomainIntelResult
from app.utils.domain_similarity import full_registered_domain

_DNS_TIMEOUT = 3.0
_SOCKET_TIMEOUT = 3.0

_DNS_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout)


def _mx_records(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=_DNS_TIMEOUT)
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except _DNS_ERRORS:
        return []


def _nameservers(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=_DNS_TIMEOUT)
        return sorted(str(r).rstrip(".") for r in answers)
    except _DNS_ERRORS:
        return []


def _dbl_listed(domain: str) -> bool:
    """Spamhaus Domain Block List — free, no key. Any A response means listed."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_SOCKET_TIMEOUT)
        socket.gethostbyname(f"{domain}.dbl.spamhaus.org")
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)


def _extract_registrar(record) -> str | None:
    registrar = getattr(record, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    return registrar if isinstance(registrar, str) else None


def _extract_age_days(record) -> tuple[str | None, int | None]:
    created = getattr(record, "creation_date", None)
    if isinstance(created, list):
        created = created[0] if created else None
    if created is None or not isinstance(created, datetime):
        return None, None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return str(created), (datetime.now(timezone.utc) - created).days


class LocalDomainIntelligenceProvider:
    name = "local_dns_whois"

    def lookup(self, domain: str) -> DomainIntelResult:
        if not domain:
            return DomainIntelResult(domain=domain, available=False, unavailable_reason="empty domain")

        result = DomainIntelResult(domain=domain, registered_domain=full_registered_domain(domain), source=self.name)

        try:
            result.mx_records = _mx_records(domain)
            result.nameservers = _nameservers(domain)
            result.dnsbl_listed = _dbl_listed(domain)
        except Exception as exc:  # DNS layer must never crash ingestion
            result.available = False
            result.unavailable_reason = f"dns lookup failed: {exc}"
            return result

        try:
            record = python_whois.whois(domain)
            result.registrar = _extract_registrar(record)
            result.created_date, result.age_days = _extract_age_days(record)
        except Exception as exc:
            # WHOIS is the flakiest dependency here (rate limits, unsupported TLDs,
            # slow registrars) — its absence must never block the rest of the pipeline.
            result.unavailable_reason = f"whois unavailable: {exc}"

        return result
