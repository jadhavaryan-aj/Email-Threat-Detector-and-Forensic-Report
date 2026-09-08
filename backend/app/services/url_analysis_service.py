"""PS component 9: per-URL lexical risk analysis. Extraction happens upstream in
eml_parser.py/url_extraction.py; this module scores the already-extracted
{raw_url, anchor_text} pairs, producing both ExtractedUrl-shaped rows (for
persistence/display) and Signal dicts (for the overall risk score). Each *type* of
finding fires its signal at most once per email regardless of how many links trip it —
one lookalike link is exactly as informative as five identical ones."""

import ipaddress
from urllib.parse import urlparse

import tldextract

from app.services.scoring_config import MAX_SUBDOMAIN_COUNT, URL_SHORTENER_DOMAINS, build_signal
from app.utils.domain_similarity import find_lookalike_brand

_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


def _is_ip_based(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registered_domain(extracted) -> str:
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain


def _anchor_hostname(anchor_text: str) -> str:
    if not anchor_text:
        return ""
    lowered = anchor_text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://") or "." in lowered):
        return ""
    candidate = anchor_text if "//" in anchor_text else f"//{anchor_text}"
    return (urlparse(candidate).hostname or "").lower()


def analyze_urls(urls: list[dict]) -> tuple[list[dict], list[dict]]:
    """Returns (extracted_url_rows, signals)."""
    rows: list[dict] = []
    signals: list[dict] = []
    fired: set[str] = set()

    def fire_once(name: str, evidence: str) -> None:
        if name not in fired:
            fired.add(name)
            signals.append(build_signal(name, evidence))

    for entry in urls:
        raw_url = entry["raw_url"]
        anchor_text = entry.get("anchor_text")
        parsed = urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()
        extracted = _tld_extractor(hostname)
        registered_domain = _registered_domain(extracted)
        subdomain_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0

        is_ip_based = _is_ip_based(hostname)
        has_punycode = "xn--" in hostname
        is_shortener = hostname in URL_SHORTENER_DOMAINS
        lookalike_brand = None if is_ip_based else find_lookalike_brand(registered_domain)

        anchor_hostname = _anchor_hostname(anchor_text or "")
        display_mismatch = bool(anchor_hostname and anchor_hostname != hostname)

        lexical_risk_score = 0
        if is_ip_based:
            lexical_risk_score += 30
            fire_once("url_ip_based", f"link host is a raw IP address: {hostname}")
        if has_punycode:
            lexical_risk_score += 25
            fire_once("url_punycode", f"punycode-encoded host: {hostname}")
        if is_shortener:
            lexical_risk_score += 15
            fire_once("url_shortener", f"shortener domain: {hostname}")
        if subdomain_count > MAX_SUBDOMAIN_COUNT:
            lexical_risk_score += 15
            fire_once("url_excessive_subdomains", f"{subdomain_count} subdomain labels in {hostname}")
        if display_mismatch:
            lexical_risk_score += 20
            fire_once(
                "url_display_mismatch",
                f"link text '{anchor_text}' does not match destination host '{hostname}'",
            )
        if lookalike_brand:
            lexical_risk_score += 40
            fire_once("url_lookalike_domain", f"'{registered_domain}' closely resembles '{lookalike_brand}'")

        rows.append(
            {
                "raw_url": raw_url,
                "anchor_text": anchor_text,
                "normalized_url": f"{parsed.scheme}://{hostname}{parsed.path}" if hostname else raw_url,
                "hostname": hostname,
                "registered_domain": registered_domain,
                "scheme": parsed.scheme,
                "is_ip_based": is_ip_based,
                "subdomain_count": subdomain_count,
                "has_punycode": has_punycode,
                "is_shortener": is_shortener,
                "display_text_mismatch": display_mismatch,
                "lookalike_of_brand": lookalike_brand,
                "lexical_risk_score": min(lexical_risk_score, 100),
            }
        )

    return rows, signals
