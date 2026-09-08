"""PS component 1: Fraudulent Email Detection Engine — produces a list of structured,
explainable signals (see models/signal.py) instead of a bare score. Combines
deterministic header/identity checks with a content analyzer (real AI via Claude when
ANTHROPIC_API_KEY is configured, see app/nlp/llm_analyzer.py — otherwise the local
keyword heuristic, app/nlp/heuristic_analyzer.py); URL-based signals come from
url_analysis_service and are merged in by ingestion_service before final scoring."""

from app.config import settings
from app.nlp.base import IntentResult
from app.nlp.heuristic_analyzer import HeuristicContentAnalyzer
from app.nlp.llm_analyzer import LLMContentAnalyzer
from app.services.scoring_config import (
    CLASSIFICATION_BANDS,
    SIGNAL_DEFINITIONS,
    SUSPICIOUS_ATTACHMENT_EXTENSIONS,
    build_signal,
)
from app.utils.domain_similarity import find_lookalike_brand

# A pattern the AI content analyzer names that has no pre-registered
# SIGNAL_DEFINITIONS entry is scored from the model's own stated confidence instead
# of requiring every possible AI-named pattern to be enumerated ahead of time. This
# cap matches the codebase's most severe *deterministic* weight (lookalike_domain_match)
# so a maximally-confident AI finding carries comparable weight to our strongest rule.
_AI_SIGNAL_MAX_SCORE = 30


def _build_content_analyzer():
    if settings.anthropic_api_key:
        return LLMContentAnalyzer(api_key=settings.anthropic_api_key)
    return HeuristicContentAnalyzer()


_content_analyzer = _build_content_analyzer()

# routing_anomaly_flags entries that map 1:1 onto a SIGNAL_DEFINITIONS key of the same name.
_ROUTING_FLAG_SIGNALS = {
    "return_path_domain_mismatch",
    "reply_to_domain_mismatch",
    "display_name_impersonation",
    "received_chain_timestamp_out_of_order",
    "received_header_missing_origin_info",
    "no_received_headers",
}

# Priority order for picking one *primary* threat category out of several that may
# apply — most specific/severe pattern wins; anything else becomes a secondary indicator.
_THREAT_CATEGORY_PRIORITY = [
    "malware_delivery",
    "business_email_compromise",
    "credential_theft",
    "spoofing",
    "spear_phishing",
    "phishing",
]


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if address and "@" in address else ""


def _routing_flag_evidence(flag: str, parsed_eml: dict, from_domain: str) -> str:
    if flag == "return_path_domain_mismatch":
        return f"From domain '{from_domain}' vs Return-Path domain '{_domain_of(parsed_eml['return_path'])}'"
    if flag == "reply_to_domain_mismatch":
        return f"From domain '{from_domain}' vs Reply-To domain '{_domain_of(parsed_eml['reply_to'])}'"
    if flag == "display_name_impersonation":
        return f"Display name '{parsed_eml.get('from_display_name', '')}' vs sending domain '{from_domain}'"
    return flag.replace("_", " ")


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.85:
        return "CRITICAL"
    if confidence >= 0.65:
        return "HIGH"
    if confidence >= 0.4:
        return "MEDIUM"
    return "LOW"


def _build_ai_signal(intent: IntentResult) -> dict:
    score = round(intent.confidence * _AI_SIGNAL_MAX_SCORE)
    evidence = "; ".join(f'"{phrase}"' for phrase in intent.evidence_phrases) or "flagged by AI content analysis"
    return {
        "name": intent.intent,
        "category": intent.category,
        "severity": _severity_from_confidence(intent.confidence),
        "score": score,
        "explanation": (
            f"AI content analysis flagged this email for "
            f"{intent.intent.replace('_', ' ')} (model confidence {intent.confidence:.0%})."
        ),
        "evidence": evidence,
    }


def generate_signals(parsed_eml: dict, header_analysis: dict) -> list[dict]:
    signals: list[dict] = []
    from_domain = _domain_of(parsed_eml["from_address"])

    spf_result = header_analysis["spf_result"]
    if spf_result == "fail":
        signals.append(build_signal("spf_fail", f"spf=fail (checked domain: {header_analysis['spf_domain']})"))
    elif spf_result == "softfail":
        signals.append(
            build_signal("spf_softfail", f"spf=softfail (checked domain: {header_analysis['spf_domain']})")
        )

    if header_analysis["dkim_result"] == "fail":
        signals.append(build_signal("dkim_fail", "dkim=fail (signature present but invalid)"))

    if header_analysis["dmarc_result"] == "fail":
        signals.append(
            build_signal(
                "dmarc_fail",
                f"dmarc=fail (policy={header_analysis['dmarc_policy'] or 'none'}, "
                f"spf_aligned={header_analysis['spf_aligned']}, dkim_aligned={header_analysis['dkim_aligned']})",
            )
        )

    for flag in header_analysis["routing_anomaly_flags"]:
        if flag in _ROUTING_FLAG_SIGNALS:
            signals.append(build_signal(flag, _routing_flag_evidence(flag, parsed_eml, from_domain)))

    lookalike_brand = find_lookalike_brand(from_domain)
    if lookalike_brand:
        signals.append(
            build_signal("lookalike_domain_match", f"'{from_domain}' closely resembles '{lookalike_brand}'")
        )

    # The content analyzer gets the technical signals already found above as context,
    # so it can reason holistically ("claims PayPal, domain doesn't match, urgent
    # tone") instead of judging body text in isolation.
    content_context = {
        "spf_result": header_analysis["spf_result"],
        "dmarc_result": header_analysis["dmarc_result"],
        "from_domain": from_domain,
        "lookalike_brand": lookalike_brand,
        "attachment_filenames": [a.get("filename", "") for a in parsed_eml.get("attachments", [])],
        "routing_anomaly_flags": header_analysis["routing_anomaly_flags"],
    }
    content_result = _content_analyzer.analyze(
        parsed_eml.get("subject", ""),
        parsed_eml.get("body_text", ""),
        parsed_eml.get("body_html", ""),
        content_context,
    )
    for intent in content_result.intents:
        if intent.intent in SIGNAL_DEFINITIONS:
            definition = SIGNAL_DEFINITIONS[intent.intent]
            score = definition["score"]
            if "score_cap" in definition:
                score = min(score * len(intent.evidence_phrases), definition["score_cap"])
            evidence = "; ".join(f'"{phrase}"' for phrase in intent.evidence_phrases)
            signals.append(build_signal(intent.intent, evidence, score_override=score))
        else:
            signals.append(_build_ai_signal(intent))

    for attachment in parsed_eml.get("attachments", []):
        filename = attachment.get("filename", "")
        if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS):
            signals.append(build_signal("suspicious_attachment", f"attachment filename: {filename}"))
            break

    return signals


def score_signals(signals: list[dict]) -> int:
    return min(sum(s["score"] for s in signals), 100)


def classify_risk_band(fraud_score: int) -> str:
    for label, (low, high) in CLASSIFICATION_BANDS.items():
        if low <= fraud_score <= high:
            return label
    return "fraud"  # score exceeded the 100-band ceiling due to rounding — treat as worst case


def classify_threat_category(signals: list[dict], fraud_score: int) -> tuple[str, list[str]]:
    """Investigator-facing category, distinct from the PS's risk-band label — derived
    from *which* signals fired, not just the total score. Returns (primary, secondary[])."""
    names = {s["name"] for s in signals}
    candidates: list[str] = []

    if "suspicious_attachment" in names:
        candidates.append("malware_delivery")
    if {"payment_diversion", "fake_invoice", "executive_impersonation"} & names:
        candidates.append("business_email_compromise")
    if "credential_harvesting" in names:
        candidates.append("credential_theft")
    if {"lookalike_domain_match", "display_name_impersonation"} & names:
        candidates.append("spoofing")
    if {"spf_fail", "dmarc_fail"} & names:
        candidates.append("spear_phishing" if len(names) >= 4 else "phishing")

    if not candidates:
        if fraud_score <= CLASSIFICATION_BANDS["legitimate"][1]:
            return "legitimate", []
        return "suspicious_unknown", []

    ordered = sorted(set(candidates), key=lambda c: _THREAT_CATEGORY_PRIORITY.index(c))
    return ordered[0], ordered[1:]
