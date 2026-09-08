"""Extracts URLs from an email body (plain text + HTML) as {raw_url, anchor_text}
pairs — anchor_text (the visible link label in HTML) is what lets url_analysis_service
later detect "link text says one thing, destination is another" deception."""

import re

from bs4 import BeautifulSoup

_URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_urls(body_text: str, body_html: str) -> list[dict]:
    seen: dict[str, dict] = {}

    for raw_url in _URL_PATTERN.findall(body_text or ""):
        raw_url = raw_url.rstrip(".,;:!?")
        seen.setdefault(raw_url, {"raw_url": raw_url, "anchor_text": None})

    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for anchor in soup.find_all("a", href=True):
            raw_url = anchor["href"].strip()
            if not raw_url.lower().startswith(("http://", "https://")):
                continue
            anchor_text = anchor.get_text(strip=True) or None
            existing = seen.get(raw_url)
            if existing and anchor_text and not existing.get("anchor_text"):
                existing["anchor_text"] = anchor_text
            else:
                seen.setdefault(raw_url, {"raw_url": raw_url, "anchor_text": anchor_text})

        for raw_url in _URL_PATTERN.findall(soup.get_text()):
            raw_url = raw_url.rstrip(".,;:!?")
            seen.setdefault(raw_url, {"raw_url": raw_url, "anchor_text": None})

    return list(seen.values())
