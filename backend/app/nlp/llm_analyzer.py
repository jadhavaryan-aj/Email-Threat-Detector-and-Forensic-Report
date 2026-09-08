"""LLM-backed ContentAnalyzer using Anthropic's Claude API — real AI analysis, used
whenever ANTHROPIC_API_KEY is configured (see detection_engine.py's provider
selection). Falls back to HeuristicContentAnalyzer's result for a given email if the
API call fails, times out, or returns something unparseable — an AI outage must
never block or crash ingestion, matching every other external-call site in this
codebase (WHOIS/DNS/ip-api/threat-intel)."""

import json
import re

import anthropic

from app.nlp.base import ContentAnalysisResult, IntentResult
from app.nlp.heuristic_analyzer import HeuristicContentAnalyzer

_MODEL = "claude-haiku-4-5-20251001"
_TIMEOUT_SECONDS = 15.0
_MAX_BODY_CHARS = 6000  # a phishing email rarely needs more context to judge; keeps calls fast/cheap

_TAXONOMY_HINT = (
    "identity_disguise, domain_spoofing_language, header_manipulation_indicators, "
    "hidden_malicious_link, attachment_deception, social_engineering_urgency, "
    "social_engineering_authority, credential_phishing_intent, financial_fraud_intent, "
    "executive_impersonation"
)

_PROMPT_TEMPLATE = """You are an email security analyst. Analyze this email for signs \
of phishing, spoofing, business email compromise, or social engineering.

TECHNICAL CONTEXT (already verified independently — treat as ground truth, don't re-derive it):
{context_block}

EMAIL SUBJECT: {subject}

EMAIL BODY:
{body}

Identify specific deception patterns actually present in THIS email. Common pattern \
names (use one of these when it fits, or a clear snake_case name of your own when it \
doesn't): {taxonomy_hint}.

For each pattern you find, rate your confidence honestly (0.0-1.0) based on how \
strong the evidence actually is in this specific email — do not inflate confidence, \
and do not report a pattern that isn't genuinely present just to fill out the list. \
It is correct and expected to return an empty list for a legitimate email.

Respond with ONLY a JSON object, no other text, in this exact shape:
{{"intents": [{{"intent": "snake_case_name", "confidence": 0.0-1.0, "category": \
"identity|content|url|infrastructure", "evidence": "short quote or reasoning from \
THIS email, not a generic description"}}]}}
"""


def _build_context_block(context: dict) -> str:
    lines = []
    if context.get("spf_result"):
        lines.append(f"- SPF: {context['spf_result']}")
    if context.get("dmarc_result"):
        lines.append(f"- DMARC: {context['dmarc_result']}")
    if context.get("from_domain"):
        lines.append(f"- Sender domain: {context['from_domain']}")
    if context.get("lookalike_brand"):
        lines.append(f"- Sender domain closely resembles: {context['lookalike_brand']} (likely typosquat)")
    if context.get("attachment_filenames"):
        lines.append(f"- Attachments: {', '.join(context['attachment_filenames'])}")
    if context.get("routing_anomaly_flags"):
        lines.append(f"- Header anomalies already detected: {', '.join(context['routing_anomaly_flags'])}")
    return "\n".join(lines) if lines else "- (no technical anomalies detected independently)"


def _extract_json(text: str) -> dict:
    text = text.strip()
    # Claude sometimes wraps JSON in prose/a code fence despite instructions;
    # extracting the outermost {...} defensively rather than requiring an exact match.
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("no JSON object found in model response")
    return json.loads(match.group(0))


class LLMContentAnalyzer:
    name = "anthropic_claude_haiku"

    def __init__(self, api_key: str):
        self._client = anthropic.Anthropic(api_key=api_key, timeout=_TIMEOUT_SECONDS)
        self._fallback = HeuristicContentAnalyzer()

    def analyze(
        self, subject: str, body_text: str, body_html: str, context: dict | None = None
    ) -> ContentAnalysisResult:
        context = context or {}
        body = (body_text or body_html or "")[:_MAX_BODY_CHARS]

        prompt = _PROMPT_TEMPLATE.format(
            context_block=_build_context_block(context),
            subject=subject or "(no subject)",
            body=body or "(empty body)",
            taxonomy_hint=_TAXONOMY_HINT,
        )

        try:
            response = self._client.messages.create(
                model=_MODEL,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            payload = _extract_json(response.content[0].text)
            intents = [
                IntentResult(
                    intent=item["intent"],
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.5)))),
                    evidence_phrases=[item["evidence"]] if item.get("evidence") else [],
                    category=item.get("category") or "content",
                )
                for item in payload.get("intents", [])
                if item.get("intent")
            ]
            return ContentAnalysisResult(intents=intents, provider=self.name)
        except Exception as exc:
            print(f"LLMContentAnalyzer failed, falling back to heuristic: {exc}")
            fallback = self._fallback.analyze(subject, body_text, body_html, context)
            return ContentAnalysisResult(intents=fallback.intents, provider=f"{self.name}_fallback_heuristic")
