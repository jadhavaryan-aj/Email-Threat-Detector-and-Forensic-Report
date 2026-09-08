"""PS component 2: Email Header and Protocol Analysis Module."""

import re

import dkim

from app.utils.received_chain_parser import detect_routing_anomalies, parse_received_chain, select_originating_ip
from app.utils.spf_dmarc import SpfResult, domains_aligned, evaluate_spf, get_dmarc_record

_DKIM_DOMAIN_PATTERN = re.compile(r"\bd=([^;]+)")


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if address and "@" in address else ""


def _extract_dkim_domain(headers: dict) -> str:
    sig = headers.get("DKIM-Signature", "")
    if isinstance(sig, list):
        sig = sig[0] if sig else ""
    match = _DKIM_DOMAIN_PATTERN.search(sig)
    return match.group(1).strip().rstrip(".") if match else ""


def _verify_dkim(raw_bytes: bytes) -> str:
    try:
        return "pass" if dkim.verify(raw_bytes) else "fail"
    except Exception:
        return "fail"


def _cross_check_authentication_results(upstream_tokens: dict, our_results: dict) -> dict:
    """Authentication-Results is stamped by whatever server received the message
    before us and is trivially forgeable — this is a transparency cross-check against
    our own independent evaluation, never a substitute for it."""
    cross_check = {}
    for mechanism, our_value in our_results.items():
        upstream_value = upstream_tokens.get(mechanism)
        if upstream_value is None:
            agreement = "no_upstream_data"
        elif upstream_value == our_value:
            agreement = "match"
        else:
            agreement = "mismatch"
        cross_check[mechanism] = {"upstream": upstream_value, "ours": our_value, "agreement": agreement}
    return cross_check


def analyze_headers(parsed_eml: dict) -> dict:
    from_address = parsed_eml["from_address"]
    from_domain = _domain_of(from_address)
    return_path = parsed_eml["return_path"]
    reply_to = parsed_eml["reply_to"]
    headers = parsed_eml["headers"]
    raw_bytes = parsed_eml["raw_bytes"]

    hops = parse_received_chain(parsed_eml["received_headers"])
    routing_anomaly_flags = detect_routing_anomalies(
        hops, from_address, reply_to, return_path, parsed_eml.get("from_display_name", "")
    )
    originating_ip = select_originating_ip(hops)

    # SPF is evaluated against the envelope sender (Return-Path), falling back
    # to the visible From: domain when no Return-Path was recorded.
    spf_checked_domain = _domain_of(return_path) or from_domain
    if originating_ip and spf_checked_domain:
        spf_result, spf_matched_domain = evaluate_spf(spf_checked_domain, originating_ip)
    else:
        spf_result, spf_matched_domain = SpfResult.NONE, spf_checked_domain
    # DMARC alignment compares From: against the domain SPF was *checked for*
    # (spf_checked_domain), not wherever a redirect=/include: chain internally
    # matched (spf_matched_domain) — e.g. gmail.com's SPF redirects to
    # _spf.google.com, but alignment is still against gmail.com itself.
    spf_aligned = spf_result == SpfResult.PASS and domains_aligned(from_domain, spf_checked_domain)

    dkim_result = "none"
    dkim_domain = ""
    if "DKIM-Signature" in headers:
        dkim_domain = _extract_dkim_domain(headers)
        dkim_result = _verify_dkim(raw_bytes)
    dkim_aligned = dkim_result == "pass" and domains_aligned(from_domain, dkim_domain)

    dmarc_tags = get_dmarc_record(from_domain) if from_domain else None
    if dmarc_tags is None:
        dmarc_result, dmarc_policy = "none", ""
    else:
        dmarc_policy = dmarc_tags.get("p", "none")
        dmarc_result = "pass" if (spf_aligned or dkim_aligned) else "fail"

    auth_cross_check = _cross_check_authentication_results(
        parsed_eml.get("authentication_results", {}).get("parsed_tokens", {}),
        {"spf": spf_result, "dkim": dkim_result, "dmarc": dmarc_result},
    )

    return {
        "spf_result": spf_result,
        "spf_domain": spf_checked_domain or "",
        "spf_matched_domain": spf_matched_domain or "",
        "dkim_result": dkim_result,
        "dkim_domain": dkim_domain,
        "dmarc_result": dmarc_result,
        "dmarc_policy": dmarc_policy,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "routing_anomaly_flags": routing_anomaly_flags,
        "received_chain": hops,
        "originating_ip": originating_ip,
        "auth_cross_check": auth_cross_check,
    }
