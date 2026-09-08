from app.nlp.base import IntentResult
from app.services import detection_engine


def _header_analysis(**overrides):
    base = {
        "spf_result": "pass",
        "spf_domain": "example.com",
        "dkim_result": "none",
        "dmarc_result": "pass",
        "dmarc_policy": "none",
        "spf_aligned": True,
        "dkim_aligned": False,
        "routing_anomaly_flags": [],
    }
    base.update(overrides)
    return base


def _parsed_eml(**overrides):
    base = {
        "from_address": "person@example.com",
        "from_display_name": "",
        "return_path": "person@example.com",
        "reply_to": "",
        "subject": "hello",
        "body_text": "just a normal email",
        "body_html": "",
        "attachments": [],
    }
    base.update(overrides)
    return base


def test_clean_email_scores_zero():
    signals = detection_engine.generate_signals(_parsed_eml(), _header_analysis())
    assert signals == []
    assert detection_engine.score_signals(signals) == 0
    assert detection_engine.classify_risk_band(0) == "legitimate"


def test_spf_fail_raises_signal_and_score():
    signals = detection_engine.generate_signals(_parsed_eml(), _header_analysis(spf_result="fail"))
    assert {s["name"] for s in signals} == {"spf_fail"}
    assert detection_engine.score_signals(signals) == 25


def test_score_never_exceeds_100():
    header = _header_analysis(spf_result="fail", dmarc_result="fail", dkim_result="fail")
    parsed = _parsed_eml(
        reply_to="other@evil.com",
        body_text="urgent immediately act now verify your account account will be locked click here "
        "within 24 hours confirm your identity unusual activity kyc reset your password immediately "
        "urgent request from ceo",
        attachments=[{"filename": "invoice.exe", "content_type": "x", "size_bytes": 1, "sha256": "a"}],
    )
    signals = detection_engine.generate_signals(parsed, header)
    assert detection_engine.score_signals(signals) <= 100


def test_suspicious_attachment_flagged():
    parsed = _parsed_eml(attachments=[{"filename": "invoice.exe", "content_type": "x", "size_bytes": 1, "sha256": "a"}])
    signals = detection_engine.generate_signals(parsed, _header_analysis())
    assert any(s["name"] == "suspicious_attachment" for s in signals)


def test_threat_category_malware_takes_priority():
    signals = [{"name": "suspicious_attachment", "score": 15}, {"name": "spf_fail", "score": 25}]
    primary, _secondary = detection_engine.classify_threat_category(signals, 40)
    assert primary == "malware_delivery"


def test_threat_category_legitimate_when_no_signals():
    primary, secondary = detection_engine.classify_threat_category([], 0)
    assert primary == "legitimate"
    assert secondary == []


def test_content_analyzer_falls_back_to_heuristic_without_api_key():
    """conftest.py doesn't set ANTHROPIC_API_KEY — this is the default CI-safe
    state, and it must select the local heuristic, not attempt a live API call."""
    from app.nlp.heuristic_analyzer import HeuristicContentAnalyzer

    assert isinstance(detection_engine._content_analyzer, HeuristicContentAnalyzer)


def test_ai_signal_scores_from_confidence_not_a_fixed_weight():
    high_confidence = detection_engine._build_ai_signal(
        IntentResult(intent="identity_disguise", confidence=0.9, evidence_phrases=["quoted line"], category="identity")
    )
    low_confidence = detection_engine._build_ai_signal(
        IntentResult(intent="identity_disguise", confidence=0.2, evidence_phrases=["quoted line"], category="identity")
    )
    assert high_confidence["score"] > low_confidence["score"]
    assert high_confidence["severity"] == "CRITICAL"
    assert low_confidence["severity"] == "LOW"
    assert high_confidence["category"] == "identity"
    assert "quoted line" in high_confidence["evidence"]


def test_ai_signal_merges_into_normal_scoring():
    """An AI-sourced signal for a pattern with no pre-registered SIGNAL_DEFINITIONS
    entry must still combine normally with deterministic signals — this is what
    lets several genuinely severe co-occurring patterns reach a high score without
    any special-cased threshold-forcing logic."""
    ai_signal = detection_engine._build_ai_signal(
        IntentResult(intent="hidden_malicious_link", confidence=0.95, evidence_phrases=["evidence"], category="url")
    )
    deterministic_signal = {"name": "spf_fail", "category": "authentication", "severity": "HIGH", "score": 25}
    total = detection_engine.score_signals([ai_signal, deterministic_signal])
    assert total == ai_signal["score"] + 25
