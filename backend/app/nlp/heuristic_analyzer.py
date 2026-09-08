"""Default ContentAnalyzer: local keyword/pattern heuristic, zero external calls —
works fully offline, per the demo-mode requirement. See base.py for the interface a
real ML/LLM provider would implement instead."""

from app.nlp.base import ContentAnalysisResult, IntentResult
from app.services.scoring_config import BEC_PATTERN_KEYWORDS, URGENCY_KEYWORDS


def _matched_keywords(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [kw for kw in keywords if kw in lowered]


class HeuristicContentAnalyzer:
    """Confidence is deliberately capped and scales with corroborating hits — this is
    explainable pattern matching, not a calibrated probabilistic model."""

    name = "local_heuristic_v1"

    def analyze(self, subject: str, body_text: str, body_html: str, context: dict | None = None) -> ContentAnalysisResult:
        # context (technical signals) is unused here — pure keyword matching has no
        # way to use it. LLMContentAnalyzer is what actually reasons over it.
        text = " ".join([subject or "", body_text or "", body_html or ""])
        intents: list[IntentResult] = []

        urgency_hits = _matched_keywords(text, URGENCY_KEYWORDS)
        if urgency_hits:
            intents.append(
                IntentResult(
                    intent="urgency",
                    confidence=min(0.95, 0.35 + 0.15 * len(urgency_hits)),
                    evidence_phrases=urgency_hits,
                )
            )

        for pattern_name, keywords in BEC_PATTERN_KEYWORDS.items():
            hits = _matched_keywords(text, keywords)
            if hits:
                intents.append(
                    IntentResult(
                        intent=pattern_name,
                        confidence=min(0.95, 0.4 + 0.2 * len(hits)),
                        evidence_phrases=hits,
                    )
                )

        return ContentAnalysisResult(intents=intents, provider=self.name)
