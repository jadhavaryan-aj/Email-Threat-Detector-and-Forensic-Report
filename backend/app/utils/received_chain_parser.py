"""Parses Received: header lines into structured hops (PS component 2)."""

import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from app.utils.domain_similarity import find_display_name_impersonation
from app.utils.ip_utils import is_public_ip

_IP_PATTERN = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")
_FROM_PATTERN = re.compile(r"from\s+(\S+)", re.IGNORECASE)
_BY_PATTERN = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)


def parse_received_chain(received_headers: list[str]) -> list[dict]:
    hops = []
    for idx, raw in enumerate(received_headers):
        normalized = " ".join(raw.split())

        from_match = _FROM_PATTERN.search(normalized)
        by_match = _BY_PATTERN.search(normalized)
        ip_match = _IP_PATTERN.search(normalized)

        timestamp = None
        if ";" in normalized:
            date_part = normalized.rsplit(";", 1)[-1].strip()
            try:
                timestamp = parsedate_to_datetime(date_part).isoformat()
            except (TypeError, ValueError, IndexError):
                timestamp = None

        hops.append(
            {
                "hop_index": idx,  # 0 = closest to recipient, last = closest to origin
                "raw": normalized,
                "from_host": from_match.group(1) if from_match else None,
                "by_host": by_match.group(1) if by_match else None,
                "ip": ip_match.group(1) if ip_match else None,
                "timestamp": timestamp,
            }
        )
    return hops


def detect_routing_anomalies(
    hops: list[dict],
    from_address: str,
    reply_to: str,
    return_path: str,
    from_display_name: str = "",
) -> list[str]:
    flags = []

    from_domain = from_address.rsplit("@", 1)[-1] if "@" in from_address else ""
    return_path_domain = return_path.rsplit("@", 1)[-1] if "@" in return_path else ""
    reply_to_domain = reply_to.rsplit("@", 1)[-1] if "@" in reply_to else ""

    if return_path and return_path_domain and from_domain and return_path_domain != from_domain:
        flags.append("return_path_domain_mismatch")

    if reply_to and reply_to_domain and from_domain and reply_to_domain != from_domain:
        flags.append("reply_to_domain_mismatch")

    if find_display_name_impersonation(from_display_name, from_domain):
        flags.append("display_name_impersonation")

    if not hops:
        flags.append("no_received_headers")
        return flags

    # Compare as aware datetimes (converted to UTC), not raw ISO strings —
    # lexicographic string order breaks once hops carry different UTC offsets.
    timestamps = [datetime.fromisoformat(h["timestamp"]).astimezone() for h in hops if h["timestamp"]]
    if len(timestamps) >= 2 and timestamps != sorted(timestamps, reverse=True):
        flags.append("received_chain_timestamp_out_of_order")

    if any(h["ip"] is None and h["from_host"] is None for h in hops):
        flags.append("received_header_missing_origin_info")

    return flags


def select_originating_ip(hops: list[dict]) -> str | None:
    """The SPF-relevant client IP: the earliest (oldest) public IP in the chain,
    i.e. the boundary crossing closest to the true sender, not internal recipient-side hops."""
    for hop in reversed(hops):
        if is_public_ip(hop.get("ip")):
            return hop["ip"]
    return None
