"""Brand-domain and brand-name similarity matching, shared by sender-domain checks
(detection_engine), URL-domain checks (url_analysis_service), and display-name
impersonation checks (received_chain_parser) so the fuzzy-matching logic exists in
exactly one place."""

import tldextract
from rapidfuzz import fuzz
from rapidfuzz.distance import Levenshtein

from app.services.scoring_config import (
    KNOWN_BRAND_DOMAINS,
    KNOWN_BRAND_NAMES,
    LOOKALIKE_MAX_DISTANCE,
    LOOKALIKE_PARTIAL_RATIO_THRESHOLD,
)

# Bundled public-suffix snapshot only — never fetch over the network. A hackathon
# demo can't depend on venue wifi being up for a PSL download on first run.
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())


def registrable_label(domain: str) -> str:
    """Just the domain label, e.g. 'sbi' for 'sbi.co.in' — for fuzzy-matching only.
    Use full_registered_domain() when you need the actual registrable domain."""
    return _tld_extractor(domain).domain if domain else ""


def full_registered_domain(domain: str) -> str:
    """The actual registrable domain, e.g. 'sbi.co.in' (not just the label 'sbi')."""
    if not domain:
        return ""
    extracted = _tld_extractor(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return extracted.domain


def find_lookalike_brand(domain: str) -> str | None:
    """Catches both whole-domain typosquats (paypa1.com vs paypal.com) and a brand
    name mutated/embedded inside a longer deceptive domain (paypa1-secure-x.com).
    Returns the real brand domain it resembles, or None."""
    if not domain:
        return None
    domain = domain.lower()
    label = registrable_label(domain)

    for brand in KNOWN_BRAND_DOMAINS:
        if domain == brand or domain.endswith("." + brand) or brand.endswith("." + domain):
            return None  # exact or legitimate subdomain relationship — not a lookalike

        brand_label = registrable_label(brand)

        whole_distance = Levenshtein.distance(label, brand_label)
        if 0 < whole_distance <= LOOKALIKE_MAX_DISTANCE:
            return brand

        if len(brand_label) >= 4:
            partial_score = fuzz.partial_ratio(label, brand_label)
            if partial_score >= LOOKALIKE_PARTIAL_RATIO_THRESHOLD:
                return brand

    return None


def find_display_name_impersonation(display_name: str, from_domain: str) -> str | None:
    """A display name that names/resembles a known brand ('PayPal Support') while the
    actual From: domain is neither that brand's real domain nor a lookalike of it (e.g.
    a free webmail address) — the classic 'Brand Support <random@gmail.com>' pattern.
    Returns the impersonated brand domain, or None."""
    if not display_name:
        return None
    display_lower = display_name.lower()
    from_domain = (from_domain or "").lower()

    for brand_domain, brand_name in KNOWN_BRAND_NAMES.items():
        if from_domain == brand_domain or from_domain.endswith("." + brand_domain):
            continue  # genuinely from the brand's own domain — not impersonation

        brand_name_lower = brand_name.lower()
        if brand_name_lower in display_lower:
            # Still not impersonation if the From: domain is itself a lookalike of
            # this same brand — that's already covered by find_lookalike_brand and
            # scored separately; this signal is specifically for "unrelated domain".
            if find_lookalike_brand(from_domain) == brand_domain:
                continue
            return brand_domain

    return None
