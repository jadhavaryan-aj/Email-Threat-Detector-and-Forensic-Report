"""Raw .eml bytes -> structured dict. Pure parsing, no analysis/scoring here."""

import hashlib
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from app.utils.url_extraction import extract_urls

_AUTH_RESULTS_TOKEN_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def _parse_authentication_results(raw_values: list[str]) -> dict:
    """Authentication-Results is stamped by the *receiving* mail system before this
    email reached us — useful as supplementary cross-check evidence, but our own
    live SPF/DKIM/DMARC evaluation (header_protocol_service) stays authoritative
    since this header is trivially forgeable by anyone relaying the message."""
    tokens: dict[str, str] = {}
    for raw in raw_values:
        for mechanism, result in _AUTH_RESULTS_TOKEN_PATTERN.findall(raw):
            tokens.setdefault(mechanism.lower(), result.lower())
    return {"raw": raw_values, "parsed_tokens": tokens}


def _mime_structure(msg: Message) -> list[str]:
    if not msg.is_multipart():
        return [msg.get_content_type()]
    return [part.get_content_type() for part in msg.walk()]


def parse_eml_bytes(raw_bytes: bytes) -> dict:
    msg: Message = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    raw_headers: dict[str, list[str] | str] = {}
    for key in msg.keys():
        values = [str(v) for v in msg.get_all(key, [])]
        raw_headers[key] = values if len(values) > 1 else values[0]

    from_name, from_address = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    return_path = msg.get("Return-Path", "").strip("<>")
    to_addresses = [addr.lower() for _, addr in getaddresses(msg.get_all("To", [])) if addr]
    cc_addresses = [addr.lower() for _, addr in getaddresses(msg.get_all("Cc", [])) if addr]

    body_text = ""
    body_html = ""
    attachments: list[dict] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    {
                        "filename": part.get_filename() or "unnamed",
                        "content_type": content_type,
                        "size_bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            elif content_type == "text/plain" and not body_text:
                body_text = part.get_content()
            elif content_type == "text/html" and not body_html:
                body_html = part.get_content()
    else:
        if msg.get_content_type() == "text/html":
            body_html = msg.get_content()
        else:
            body_text = msg.get_content()

    return {
        "subject": msg.get("Subject", "") or "",
        "from_display_name": from_name,
        "from_address": from_address.lower(),
        "reply_to": reply_to.lower(),
        "return_path": return_path.lower(),
        "to_addresses": to_addresses,
        "cc_addresses": cc_addresses,
        "date_header": msg.get("Date", "") or "",
        "message_id": msg.get("Message-ID", "") or "",
        "authentication_results": _parse_authentication_results(msg.get_all("Authentication-Results", [])),
        "mime_structure": _mime_structure(msg),
        "headers": raw_headers,
        # Received headers appear top-to-bottom = most-recent-hop-first
        # (each relay prepends its own line above the ones before it).
        "received_headers": [str(v) for v in msg.get_all("Received", [])],
        "body_text": body_text,
        "body_html": body_html,
        "urls": extract_urls(body_text, body_html),
        "attachments": attachments,
        "raw_bytes": raw_bytes,
    }


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
