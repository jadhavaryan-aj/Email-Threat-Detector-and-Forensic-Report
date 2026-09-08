"""Integration tests against the real, DNS-verified demo fixtures. These need
live network access (real SPF/DMARC/WHOIS/ip-api lookups) by design — this
mirrors exactly how the app behaves for a real user, per the project's
"no mocked results" philosophy. See sample_emails/README.md for why each
fixture scores the way it does."""


def _upload(client, load_eml, filename, source_url=None):
    data = {"source_url": source_url} if source_url is not None else {}
    response = client.post(
        "/api/cases/upload",
        files={"file": (filename, load_eml(filename), "message/rfc822")},
        data=data,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_clean_fixture_scores_legitimate(client, load_eml):
    upload = _upload(client, load_eml, "clean_legit_001.eml")
    case = client.get(f"/api/cases/{upload['case_id']}").json()
    detection = case["email_analyses"][0]["detection_result"]
    assert detection["classification_label"] == "legitimate"
    assert detection["fraud_score"] == 0


def test_spoofed_fixture_scores_high_risk(client, load_eml):
    upload = _upload(client, load_eml, "spf_fail_spoofed_001.eml")
    case = client.get(f"/api/cases/{upload['case_id']}").json()
    header = case["email_analyses"][0]["header_auth_result"]
    detection = case["email_analyses"][0]["detection_result"]
    assert header["spf_result"] == "fail"
    assert header["dmarc_result"] == "fail"
    assert detection["fraud_score"] >= 60


def test_lookalike_bec_fixture_scores_highest(client, load_eml):
    upload = _upload(client, load_eml, "dmarc_fail_lookalike_bec_001.eml")
    case = client.get(f"/api/cases/{upload['case_id']}").json()
    detection = case["email_analyses"][0]["detection_result"]
    signals = case["email_analyses"][0]["signals"]
    assert detection["fraud_score"] >= 80
    assert any(s["name"] == "lookalike_domain_match" for s in signals)


def test_upload_rejects_oversized_file(client):
    huge_content = b"x" * (11 * 1024 * 1024)
    response = client.post("/api/cases/upload", files={"file": ("huge.eml", huge_content, "message/rfc822")})
    assert response.status_code == 413


def test_upload_rejects_non_eml_extension(client):
    response = client.post("/api/cases/upload", files={"file": ("not-an-email.txt", b"hello", "text/plain")})
    assert response.status_code == 400


def test_dashboard_stats_reflects_uploads(client, load_eml):
    _upload(client, load_eml, "clean_legit_001.eml")
    stats = client.get("/api/dashboard/stats").json()
    assert stats["total_cases"] >= 1


def test_report_pdf_is_generated(client, load_eml):
    upload = _upload(client, load_eml, "clean_legit_001.eml")
    response = client.get(f"/api/cases/{upload['case_id']}/report")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content[:4] == b"%PDF"


def test_correlation_detects_shared_ip_across_cases(client, load_eml):
    """Both spoofed-SBI-style fixtures below share IP 1.1.1.1 in this synthetic
    test — confirms IndicatorObservation-based correlation actually works."""
    raw_a = (
        b"From: a@sbi.co.in\r\n"
        b"Received: from x (x [1.1.1.1]) by y; Sun, 06 Sep 2026 03:41:55 +0000\r\n"
        b"Subject: test a\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
    )
    raw_b = (
        b"From: b@icicibank.com\r\n"
        b"Received: from x (x [1.1.1.1]) by y; Sun, 06 Sep 2026 03:41:55 +0000\r\n"
        b"Subject: test b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
    )
    upload_a = client.post("/api/cases/upload", files={"file": ("a.eml", raw_a, "message/rfc822")}).json()
    upload_b = client.post("/api/cases/upload", files={"file": ("b.eml", raw_b, "message/rfc822")}).json()

    indicators = client.get(f"/api/cases/{upload_a['case_id']}/indicators").json()
    shared_ips = {i["indicator_value"] for i in indicators["shared_infrastructure"] if i["indicator_type"] == "ip"}
    assert "1.1.1.1" in shared_ips

    graph = client.get(f"/api/cases/{upload_a['case_id']}/graph").json()
    other_case_node = f"case:{upload_b['case_id']}"
    assert any(n["id"] == other_case_node for n in graph["nodes"])


def test_report_escapes_malicious_subject_html():
    """Regression test for the LFI/HTML-injection vulnerability found during a
    security review: without autoescape, a crafted Subject containing
    <img src="file:///..."> would be interpreted as live HTML by xhtml2pdf's
    parser (which fetches image sources), not rendered as inert text."""
    from app.services.report_service import _env

    assert _env.autoescape is True


def test_source_url_round_trips(client, load_eml):
    """The Chrome extension passes source_url on upload (a Gmail deep link) —
    confirm it's stored and returned on both list and detail endpoints."""
    gmail_url = "https://mail.google.com/mail/u/0/#inbox/abc123"
    upload = _upload(client, load_eml, "clean_legit_001.eml", source_url=gmail_url)

    case_detail = client.get(f"/api/cases/{upload['case_id']}").json()
    assert case_detail["email_analyses"][0]["source_url"] == gmail_url

    case_list = client.get("/api/cases").json()
    listed = next(c for c in case_list if c["case_id"] == upload["case_id"])
    assert listed["source_url"] == gmail_url


def test_source_url_rejects_non_http_scheme(client, load_eml):
    """A crafted javascript:/data: URI must never be stored as a source_url —
    the dashboard renders it directly into a clickable link."""
    upload = _upload(client, load_eml, "clean_legit_001.eml", source_url="javascript:alert(1)")
    case_detail = client.get(f"/api/cases/{upload['case_id']}").json()
    assert case_detail["email_analyses"][0]["source_url"] == ""


def test_min_score_filter(client, load_eml):
    _upload(client, load_eml, "clean_legit_001.eml")  # scores 0
    upload_high = _upload(client, load_eml, "dmarc_fail_lookalike_bec_001.eml")  # scores >= 80

    filtered = client.get("/api/cases?min_score=90").json()
    assert all(c["fraud_score"] >= 90 for c in filtered)
    assert any(c["case_id"] == upload_high["case_id"] for c in filtered)

    unfiltered = client.get("/api/cases").json()
    assert len(unfiltered) >= len(filtered)


def test_attribution_endpoint_returns_spoofed_domain_for_lookalike_fixture(client, load_eml):
    upload = _upload(client, load_eml, "dmarc_fail_lookalike_bec_001.eml")
    attribution = client.get(f"/api/cases/{upload['case_id']}/attribution").json()
    assert attribution["scenario"] == "spoofed_domain"
    assert attribution["confidence"] > 0
    assert attribution["reasoning"]


def test_attribution_endpoint_returns_insufficient_data_for_clean_fixture(client, load_eml):
    upload = _upload(client, load_eml, "clean_legit_001.eml")
    attribution = client.get(f"/api/cases/{upload['case_id']}/attribution").json()
    assert attribution["scenario"] == "insufficient_data"


def test_evidence_log_is_chained_and_valid_after_ingestion(client, load_eml):
    upload = _upload(client, load_eml, "clean_legit_001.eml")
    log = client.get(f"/api/cases/{upload['case_id']}/evidence-log").json()

    assert log["valid"] is True
    assert log["first_broken_index"] is None
    assert len(log["entries"]) == 2  # "ingested" then "analyzed"
    assert log["entries"][0]["action"] == "ingested"
    assert log["entries"][0]["prev_entry_hash"] == "genesis"
    assert log["entries"][1]["action"] == "analyzed"
    assert log["entries"][1]["prev_entry_hash"] == log["entries"][0]["entry_hash"]


def test_evidence_log_detects_tampering(client, load_eml):
    """A tampered row must break live verification — this is the actual
    forensic-integrity guarantee, so it's exercised end-to-end against the
    real database rather than just the pure hash_chain unit tests."""
    from sqlmodel import Session, select

    from app.db import engine
    from app.models.forensics import EvidenceLogEntry

    upload = _upload(client, load_eml, "clean_legit_001.eml")

    with Session(engine) as session:
        entry = session.exec(
            select(EvidenceLogEntry).where(EvidenceLogEntry.case_id == upload["case_id"])
        ).first()
        entry.payload = {**entry.payload, "sha256": "tampered"}
        session.add(entry)
        session.commit()

    log = client.get(f"/api/cases/{upload['case_id']}/evidence-log").json()
    assert log["valid"] is False
    assert log["first_broken_index"] == 0
