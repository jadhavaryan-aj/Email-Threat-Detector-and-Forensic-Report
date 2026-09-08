"""PS component 8: modular content-analysis interface. The default implementation
(heuristic_analyzer.py) is a local keyword/pattern heuristic — no external ML/LLM call.
llm_analyzer.py implements this same protocol with a real Claude API call, used when
ANTHROPIC_API_KEY is configured; nothing else in the pipeline needs to change to swap
between them (see detection_engine.py's provider selection). Never present the
heuristic's confidence numbers as if they came from a trained/calibrated model — the
LLM's confidence is real (model-stated), the heuristic's is a hand-tuned proxy.

`context` carries the technical signals already computed for this email (SPF/DMARC
result, whether the domain is a detected lookalike, attachment filenames, ...) so an
implementation can reason holistically instead of judging body text in isolation —
e.g. "claims to be PayPal, domain doesn't match, AND uses urgency language" is a much
stronger signal taken together than any one part alone. The heuristic implementation
ignores it; the LLM implementation includes it in the prompt."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class IntentResult:
    intent: str
    confidence: float
    evidence_phrases: list[str] = field(default_factory=list)
    category: str = "content"  # authentication | identity | content | infrastructure | reputation | url


@dataclass
class ContentAnalysisResult:
    intents: list[IntentResult]
    provider: str


class ContentAnalyzer(Protocol):
    def analyze(self, subject: str, body_text: str, body_html: str, context: dict) -> ContentAnalysisResult: ...
