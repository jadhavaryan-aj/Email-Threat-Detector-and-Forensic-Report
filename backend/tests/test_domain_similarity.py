from app.utils.domain_similarity import find_display_name_impersonation, find_lookalike_brand, full_registered_domain


def test_exact_brand_domain_is_not_lookalike():
    assert find_lookalike_brand("paypal.com") is None


def test_typosquat_detected():
    assert find_lookalike_brand("paypa1.com") == "paypal.com"


def test_brand_embedded_in_longer_domain_detected():
    assert find_lookalike_brand("paypa1-secure-verification.com") == "paypal.com"


def test_unrelated_domain_not_flagged():
    assert find_lookalike_brand("mycompany.com") is None


def test_short_unrelated_domain_not_false_positive():
    """Regression test for the example.com -> apple.com false positive found
    during browser testing, fixed by raising LOOKALIKE_PARTIAL_RATIO_THRESHOLD to 85."""
    assert find_lookalike_brand("example.com") is None


def test_display_name_impersonation_flags_unrelated_domain():
    assert find_display_name_impersonation("PayPal Support", "gmail.com") == "paypal.com"


def test_display_name_impersonation_not_flagged_for_real_domain():
    assert find_display_name_impersonation("PayPal Support", "paypal.com") is None


def test_full_registered_domain_includes_multi_part_suffix():
    """Regression test: registrable_label() alone returns just 'sbi', not the
    full registrable domain 'sbi.co.in' needed for domain-intelligence lookups."""
    assert full_registered_domain("sbi.co.in") == "sbi.co.in"
    assert full_registered_domain("mail.sbi.co.in") == "sbi.co.in"
