"""Real, live-DNS SPF and DMARC evaluation (RFC 7208 / RFC 7489 core mechanisms).

No third-party SPF/DMARC library is used — pyspf is effectively unmaintained and
checkdmarc only audits a domain's *published* policy, it doesn't evaluate a specific
message. This implements the actual per-message evaluation (given a sender IP and
checked domain) against real DNS, covering the mechanisms real-world SPF records use:
ip4/ip6/include/redirect/a/mx/all.
"""

import ipaddress

import dns.exception
import dns.resolver


class SpfResult:
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


_QUALIFIER_MAP = {
    "+": SpfResult.PASS,
    "-": SpfResult.FAIL,
    "~": SpfResult.SOFTFAIL,
    "?": SpfResult.NEUTRAL,
}

# NXDOMAIN/NoAnswer are a *definitive* answer from a working resolver — the record
# genuinely doesn't exist, no retry needed. NoNameservers/Timeout are *transient* —
# found via a real live lookup for sbi.co.in's DMARC record that failed mid-session
# despite the record being genuinely published (confirmed by re-querying seconds
# later); treating that identically to "no record" would silently under-score a
# real spoofing attempt. One retry clears most of these.
_DEFINITIVE_DNS_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)
_TRANSIENT_DNS_ERRORS = (dns.resolver.NoNameservers, dns.exception.Timeout)
_DNS_ERRORS = _DEFINITIVE_DNS_ERRORS + _TRANSIENT_DNS_ERRORS


def _resolve_with_retry(domain: str, rdtype: str, timeout: float, retries: int = 1):
    for attempt in range(retries + 1):
        try:
            return dns.resolver.resolve(domain, rdtype, lifetime=timeout)
        except _DEFINITIVE_DNS_ERRORS:
            return None
        except _TRANSIENT_DNS_ERRORS:
            if attempt == retries:
                return None
    return None


def _txt_records(domain: str, timeout: float = 4.0) -> list[str]:
    answers = _resolve_with_retry(domain, "TXT", timeout)
    if answers is None:
        return []
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answers]


def get_spf_record(domain: str) -> str | None:
    for record in _txt_records(domain):
        if record.lower().startswith("v=spf1"):
            return record
    return None


def get_dmarc_record(domain: str) -> dict[str, str] | None:
    for record in _txt_records(f"_dmarc.{domain}"):
        if record.lower().startswith("v=dmarc1"):
            tags = {}
            for part in record.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return tags
    return None


def _ip_in_cidr(ip_obj, cidr_value: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr_value, strict=False)
    except ValueError:
        return False
    return network.version == ip_obj.version and ip_obj in network


def _resolve_addresses(hostname: str, ip_version: int, timeout: float = 4.0) -> list[str]:
    rdtype = "AAAA" if ip_version == 6 else "A"
    answers = _resolve_with_retry(hostname, rdtype, timeout)
    return [str(a) for a in answers] if answers is not None else []


def _matches_a(hostname: str, ip_obj) -> bool:
    return str(ip_obj) in _resolve_addresses(hostname, ip_obj.version)


def _matches_mx(hostname: str, ip_obj, timeout: float = 4.0) -> bool:
    answers = _resolve_with_retry(hostname, "MX", timeout)
    if answers is None:
        return False
    return any(_matches_a(str(rdata.exchange).rstrip("."), ip_obj) for rdata in answers)


def evaluate_spf(domain: str, sender_ip: str, _depth: int = 0) -> tuple[str, str]:
    """Returns (result, evaluated_domain) using live DNS."""
    if _depth > 10 or not domain:
        return SpfResult.PERMERROR, domain

    try:
        ip_obj = ipaddress.ip_address(sender_ip)
    except ValueError:
        return SpfResult.NONE, domain

    record = get_spf_record(domain)
    if record is None:
        return SpfResult.NONE, domain

    redirect_domain = None
    for term in record.split()[1:]:  # drop leading "v=spf1"
        qualifier = SpfResult.PASS
        body = term
        if term and term[0] in _QUALIFIER_MAP:
            qualifier = _QUALIFIER_MAP[term[0]]
            body = term[1:]
        lower_body = body.lower()

        if lower_body == "all":
            return qualifier, domain

        if lower_body.startswith("ip4:") or lower_body.startswith("ip6:"):
            if _ip_in_cidr(ip_obj, body.split(":", 1)[1]):
                return qualifier, domain

        elif lower_body.startswith("include:"):
            sub_result, _ = evaluate_spf(body.split(":", 1)[1], sender_ip, _depth + 1)
            if sub_result == SpfResult.PASS:
                return qualifier, domain

        elif lower_body.startswith("redirect="):
            redirect_domain = body.split("=", 1)[1]

        elif lower_body == "a" or lower_body.startswith("a:") or lower_body.startswith("a/"):
            target = body.split(":", 1)[1].split("/", 1)[0] if ":" in body else domain
            if _matches_a(target, ip_obj):
                return qualifier, domain

        elif lower_body == "mx" or lower_body.startswith("mx:") or lower_body.startswith("mx/"):
            target = body.split(":", 1)[1].split("/", 1)[0] if ":" in body else domain
            if _matches_mx(target, ip_obj):
                return qualifier, domain

    if redirect_domain:
        return evaluate_spf(redirect_domain, sender_ip, _depth + 1)

    return SpfResult.NEUTRAL, domain


def domains_aligned(from_domain: str, checked_domain: str) -> bool:
    """DMARC 'relaxed' alignment: exact match or parent/subdomain relationship."""
    from_domain = (from_domain or "").lower().rstrip(".")
    checked_domain = (checked_domain or "").lower().rstrip(".")
    if not from_domain or not checked_domain:
        return False
    return (
        from_domain == checked_domain
        or from_domain.endswith("." + checked_domain)
        or checked_domain.endswith("." + from_domain)
    )
