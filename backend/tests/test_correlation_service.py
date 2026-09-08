"""Unit tests for assess_attribution_scenario() built directly against the DB
(not through full ingestion) so each rule branch can be exercised in isolation
without depending on live DNS/WHOIS/ip-api lookups."""

from sqlmodel import Session

from app.db import engine
from app.models.case import Case, DetectionResult, EmailAnalysis, HeaderAuthResult
from app.models.correlation import IndicatorObservation
from app.models.intelligence import IpIntelligence
from app.models.signal import Signal
from app.services.correlation_service import assess_attribution_scenario


def _make_case(
    session: Session,
    *,
    fraud_score: int = 80,
    threat_category: str = "phishing",
    spf: str = "fail",
    dkim: str = "fail",
    dmarc: str = "fail",
    spf_aligned: bool = False,
    dkim_aligned: bool = False,
    signal_names: list[str] = (),
    ip: str | None = None,
    is_vpn: bool | None = None,
) -> int:
    case = Case(title="test case")
    session.add(case)
    session.flush()

    email = EmailAnalysis(case_id=case.id, raw_eml_path="x", raw_eml_sha256="x")
    session.add(email)
    session.flush()

    session.add(
        DetectionResult(
            email_analysis_id=email.id,
            classification_label="phishing",
            fraud_score=fraud_score,
            threat_category=threat_category,
        )
    )
    session.add(
        HeaderAuthResult(
            email_analysis_id=email.id,
            spf_result=spf,
            dkim_result=dkim,
            dmarc_result=dmarc,
            spf_aligned=spf_aligned,
            dkim_aligned=dkim_aligned,
        )
    )
    for name in signal_names:
        session.add(
            Signal(email_analysis_id=email.id, name=name, category="content", severity="HIGH", score=20, explanation="x")
        )
    if ip:
        session.add(IpIntelligence(email_analysis_id=email.id, ip=ip, is_vpn_or_proxy_or_tor=is_vpn, available=True))
        session.add(IndicatorObservation(case_id=case.id, email_analysis_id=email.id, indicator_type="ip", indicator_value=ip))

    session.commit()
    return case.id


def test_low_score_case_is_insufficient_data():
    with Session(engine) as session:
        case_id = _make_case(session, fraud_score=10, spf="pass", dkim="pass", dmarc="pass", spf_aligned=True, dkim_aligned=True)
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "insufficient_data"
    assert result["confidence"] == 0.0


def test_vpn_origin_is_anonymized_infrastructure():
    with Session(engine) as session:
        case_id = _make_case(session, ip="45.10.10.10", is_vpn=True)
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "anonymized_infrastructure"
    assert "VPN/proxy/Tor" in result["reasoning"]


def test_clean_auth_with_social_engineering_is_compromised_account():
    with Session(engine) as session:
        case_id = _make_case(
            session,
            spf="pass",
            dkim="pass",
            dmarc="pass",
            spf_aligned=True,
            dkim_aligned=True,
            signal_names=["payment_diversion", "urgency"],
        )
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "compromised_account"
    assert "SPF, DKIM, and DMARC all pass" in result["reasoning"]


def test_lookalike_domain_is_spoofed_domain():
    with Session(engine) as session:
        case_id = _make_case(session, signal_names=["lookalike_domain_match"])
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "spoofed_domain"
    assert "lookalike_domain_match" in result["reasoning"]


def test_auth_failure_without_identity_signal_is_still_spoofed_domain():
    with Session(engine) as session:
        case_id = _make_case(session, spf="fail", dkim="fail", dmarc="fail", spf_aligned=False, dkim_aligned=False)
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "spoofed_domain"


def test_no_strong_pattern_falls_back_to_direct_actor():
    with Session(engine) as session:
        case_id = _make_case(
            session,
            spf="pass",
            dkim="pass",
            dmarc="pass",
            spf_aligned=True,
            dkim_aligned=True,
            ip="203.0.113.5",
            is_vpn=False,
        )
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "direct_actor"


def test_shared_flagged_ip_across_cases_is_anonymized_infrastructure():
    with Session(engine) as session:
        # A second case observes the same reputation-flagged IP first.
        _make_case(session, ip="198.51.100.9", is_vpn=False, signal_names=["ip_reputation_flagged"])
        case_id = _make_case(session, ip="198.51.100.9", is_vpn=False, signal_names=["ip_reputation_flagged"])
        result = assess_attribution_scenario(session, case_id)
    assert result["scenario"] == "anonymized_infrastructure"
    assert "shared attack infrastructure" in result["reasoning"]
