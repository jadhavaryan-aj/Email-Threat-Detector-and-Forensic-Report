from app.utils.eml_parser import parse_eml_bytes


def test_parses_clean_fixture(load_eml):
    parsed = parse_eml_bytes(load_eml("clean_legit_001.eml"))
    assert parsed["from_address"] == "alex.mentor@gmail.com"
    assert parsed["subject"] == "Re: Mentorship session this Thursday"
    assert len(parsed["received_headers"]) == 2
    assert parsed["attachments"] == []
    assert parsed["urls"] == []


def test_parses_bec_fixture_with_attachment(load_eml):
    parsed = parse_eml_bytes(load_eml("dmarc_fail_lookalike_bec_001.eml"))
    assert parsed["from_address"] == "billing@paypa1-secure-verification.com"
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "Payment_Instructions.js"


def test_handles_malformed_content_gracefully():
    """The pipeline must never crash on unusual/malformed input (PS section 25)."""
    garbage = b"this is not a real email \x00\x01\x02 at all"
    parsed = parse_eml_bytes(garbage)
    assert parsed["from_address"] == ""
    assert parsed["subject"] == ""


def test_to_cc_addresses_parsed():
    raw = (
        b"From: a@example.com\r\nTo: b@example.com, c@example.com\r\n"
        b"Cc: d@example.com\r\nSubject: test\r\n\r\nbody\r\n"
    )
    parsed = parse_eml_bytes(raw)
    assert parsed["to_addresses"] == ["b@example.com", "c@example.com"]
    assert parsed["cc_addresses"] == ["d@example.com"]


def test_authentication_results_parsed():
    raw = (
        b"From: a@example.com\r\n"
        b"Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=a@example.com; "
        b"dkim=fail header.i=@example.com; dmarc=pass\r\n"
        b"Subject: test\r\n\r\nbody\r\n"
    )
    parsed = parse_eml_bytes(raw)
    assert parsed["authentication_results"]["parsed_tokens"] == {"spf": "pass", "dkim": "fail", "dmarc": "pass"}
