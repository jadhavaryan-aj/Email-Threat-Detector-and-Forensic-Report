from app.utils.received_chain_parser import detect_routing_anomalies, parse_received_chain, select_originating_ip

_HOPS = [
    "from a (a [127.0.0.1]) by b; Sun, 06 Sep 2026 10:16:00 +0000",
    "from c (c [74.125.20.41]) by b; Sun, 06 Sep 2026 10:15:45 +0000",
]


def test_parses_hops_in_order():
    hops = parse_received_chain(_HOPS)
    assert len(hops) == 2
    assert hops[0]["ip"] == "127.0.0.1"
    assert hops[1]["ip"] == "74.125.20.41"


def test_select_originating_ip_skips_private():
    hops = parse_received_chain(_HOPS)
    assert select_originating_ip(hops) == "74.125.20.41"


def test_no_received_headers_flag():
    flags = detect_routing_anomalies([], "a@x.com", "", "")
    assert "no_received_headers" in flags


def test_identity_checks_still_run_without_received_headers():
    """Regression test: the identity mismatch checks must not be skipped just
    because there are no Received headers — these are independent concerns."""
    flags = detect_routing_anomalies([], "a@sbi.co.in", "x@protonmail.com", "a@sbi.co.in")
    assert "reply_to_domain_mismatch" in flags
    assert "no_received_headers" in flags


def test_reply_to_mismatch_detected():
    hop = {"hop_index": 0, "ip": "1.1.1.1", "from_host": "x", "by_host": "y", "timestamp": None}
    flags = detect_routing_anomalies([hop], "a@sbi.co.in", "x@protonmail.com", "a@sbi.co.in")
    assert "reply_to_domain_mismatch" in flags
    assert "return_path_domain_mismatch" not in flags


def test_display_name_impersonation_detected():
    hop = {"hop_index": 0, "ip": "1.1.1.1", "from_host": "x", "by_host": "y", "timestamp": None}
    flags = detect_routing_anomalies([hop], "random@gmail.com", "", "", from_display_name="PayPal Support")
    assert "display_name_impersonation" in flags
