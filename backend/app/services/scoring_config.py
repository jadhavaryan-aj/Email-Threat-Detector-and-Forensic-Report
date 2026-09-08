"""All tunable fraud-scoring signal definitions/keyword lists in one place, for fast
demo-time tuning. Every signal the detection engine can raise is defined here once —
category/severity/score/explanation — so detection_engine.py never hardcodes weights."""

# name -> {category, severity, score, explanation}. `evidence` (the specific matched
# fact for *this* email) is filled in per-email by detection_engine.py, not here.
SIGNAL_DEFINITIONS: dict[str, dict] = {
    # --- authentication ---
    "spf_fail": {
        "category": "authentication",
        "severity": "HIGH",
        "score": 25,
        "explanation": (
            "The sender's domain published an SPF policy that does not authorize the "
            "server this email was actually sent from."
        ),
    },
    "spf_softfail": {
        "category": "authentication",
        "severity": "MEDIUM",
        "score": 12,
        "explanation": (
            "The sender's domain's SPF policy weakly disallows the sending server "
            "(soft-fail) — a milder authentication mismatch than a hard fail."
        ),
    },
    "dkim_fail": {
        "category": "authentication",
        "severity": "MEDIUM",
        "score": 10,
        "explanation": (
            "The email carries a DKIM signature that fails cryptographic "
            "verification, meaning it may have been altered in transit or the "
            "signature is invalid."
        ),
    },
    "dmarc_fail": {
        "category": "authentication",
        "severity": "HIGH",
        "score": 20,
        "explanation": (
            "The visible From: domain does not align with the authenticated sending "
            "identity (neither SPF nor DKIM passed and aligned) — this is exactly "
            "what DMARC is designed to catch."
        ),
    },
    # --- identity ---
    "return_path_domain_mismatch": {
        "category": "identity",
        "severity": "MEDIUM",
        "score": 10,
        "explanation": (
            "The bounce address (Return-Path) uses a different domain than the "
            "visible sender, which is unusual for legitimate mail."
        ),
    },
    "reply_to_domain_mismatch": {
        "category": "identity",
        "severity": "HIGH",
        "score": 15,
        "explanation": (
            "Replies to this email would be redirected to a different domain than "
            "the visible sender — a common business-email-compromise technique."
        ),
    },
    "display_name_impersonation": {
        "category": "identity",
        "severity": "HIGH",
        "score": 20,
        "explanation": (
            "The display name claims to be a known organization, but the actual "
            "sending domain has no relationship to that organization."
        ),
    },
    "lookalike_domain_match": {
        "category": "identity",
        "severity": "CRITICAL",
        "score": 30,
        "explanation": (
            "The sending domain closely resembles a well-known organization's "
            "domain, consistent with typosquatting/domain spoofing."
        ),
    },
    # --- infrastructure / routing ---
    "received_chain_timestamp_out_of_order": {
        "category": "infrastructure",
        "severity": "MEDIUM",
        "score": 8,
        "explanation": (
            "The chronological order of mail relay timestamps is inconsistent, "
            "which can indicate a forged or manually constructed header chain."
        ),
    },
    "received_header_missing_origin_info": {
        "category": "infrastructure",
        "severity": "LOW",
        "score": 5,
        "explanation": (
            "One or more relay hops in the header chain are missing identifying "
            "information (IP/hostname)."
        ),
    },
    "no_received_headers": {
        "category": "infrastructure",
        "severity": "MEDIUM",
        "score": 5,
        "explanation": (
            "The message has no Received headers at all, which is unusual for mail "
            "that has passed through standard SMTP relays."
        ),
    },
    "ip_reputation_flagged": {
        "category": "reputation",
        "severity": "CRITICAL",
        "score": 20,
        "explanation": "A DNS-based reputation list or threat-intelligence source has flagged the observed sending IP as a known source of spam/abuse.",
    },
    "domain_reputation_flagged": {
        "category": "reputation",
        "severity": "HIGH",
        "score": 15,
        "explanation": "A DNS-based reputation list or threat-intelligence source has flagged the sending domain as a known source of spam/abuse.",
    },
    # --- content (NLP heuristic intents) ---
    "urgency": {
        "category": "content",
        "severity": "MEDIUM",
        "score": 5,
        "score_cap": 15,
        "explanation": (
            "The message uses urgency or time-pressure language, a common "
            "social-engineering tactic to short-circuit careful review."
        ),
    },
    "payment_diversion": {
        "category": "content",
        "severity": "CRITICAL",
        "score": 15,
        "explanation": (
            "The message requests changes to payment/banking details — a hallmark "
            "of business-email-compromise fraud."
        ),
    },
    "fake_invoice": {
        "category": "content",
        "severity": "HIGH",
        "score": 15,
        "explanation": "The message references an invoice/payment demand consistent with fake-invoice fraud.",
    },
    "credential_harvesting": {
        "category": "content",
        "severity": "CRITICAL",
        "score": 15,
        "explanation": (
            "The message asks the recipient to enter or confirm credentials, "
            "consistent with a credential-phishing attempt."
        ),
    },
    "executive_impersonation": {
        "category": "content",
        "severity": "HIGH",
        "score": 15,
        "explanation": "The message's phrasing impersonates urgency from an executive, a common CEO-fraud pattern.",
    },
    "suspicious_attachment": {
        "category": "content",
        "severity": "HIGH",
        "score": 15,
        "explanation": "The message includes an attachment with a file extension commonly used to deliver malware.",
    },
    # --- url ---
    "url_ip_based": {
        "category": "url",
        "severity": "HIGH",
        "score": 15,
        "explanation": (
            "A link points directly to a raw IP address rather than a domain name, "
            "a technique used to evade domain-based reputation checks."
        ),
    },
    "url_punycode": {
        "category": "url",
        "severity": "HIGH",
        "score": 12,
        "explanation": (
            "A link uses punycode (internationalized domain encoding), sometimes "
            "used to visually spoof a trusted domain."
        ),
    },
    "url_shortener": {
        "category": "url",
        "severity": "MEDIUM",
        "score": 8,
        "explanation": "A link uses a URL-shortening service, which hides the true destination from the recipient.",
    },
    "url_excessive_subdomains": {
        "category": "url",
        "severity": "MEDIUM",
        "score": 8,
        "explanation": (
            "A link uses an unusually large number of subdomains, a technique "
            "sometimes used to obscure the real destination domain."
        ),
    },
    "url_display_mismatch": {
        "category": "url",
        "severity": "HIGH",
        "score": 15,
        "explanation": "The visible link text does not match where the link actually leads.",
    },
    "url_lookalike_domain": {
        "category": "url",
        "severity": "CRITICAL",
        "score": 25,
        "explanation": "A link's domain closely resembles a well-known organization's domain.",
    },
}

# label -> (min_score, max_score), inclusive. Matches the PS's own 5-way wording.
CLASSIFICATION_BANDS: dict[str, tuple[int, int]] = {
    "legitimate": (0, 19),
    "suspicious": (20, 39),
    "impersonated": (40, 59),
    "phishing": (60, 79),
    "fraud": (80, 100),
}

# Small, hackathon-scope reference set of frequently-impersonated brand domains
# for typosquat/lookalike-domain detection (edit-distance based).
KNOWN_BRAND_DOMAINS: list[str] = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "sbi.co.in",
    "icicibank.com",
    "hdfcbank.com",
    "irctc.co.in",
    "onlinesbi.sbi",
]
LOOKALIKE_MAX_DISTANCE = 2  # edit-distance threshold; 0 (exact match) is excluded separately
LOOKALIKE_PARTIAL_RATIO_THRESHOLD = 85  # catches a brand mutated/embedded in a longer domain

# domain -> canonical display name, for display-name-impersonation detection
# ("PayPal Support <random@gmail.com>" — display name claims a brand, From: domain doesn't).
KNOWN_BRAND_NAMES: dict[str, str] = {
    "paypal.com": "PayPal",
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "amazon.com": "Amazon",
    "sbi.co.in": "State Bank of India",
    "onlinesbi.sbi": "SBI",
    "icicibank.com": "ICICI Bank",
    "hdfcbank.com": "HDFC Bank",
    "irctc.co.in": "IRCTC",
}

URGENCY_KEYWORDS: list[str] = [
    "urgent",
    "immediately",
    "act now",
    "verify your account",
    "account suspended",
    "account will be locked",
    "click here",
    "limited time",
    "within 24 hours",
    "confirm your identity",
    "unusual activity",
    "kyc",
]

BEC_PATTERN_KEYWORDS: dict[str, list[str]] = {
    "payment_diversion": [
        "update your bank details",
        "change of account",
        "new payment instructions",
        "new account details",
        "routing number",
    ],
    "fake_invoice": [
        "invoice attached",
        "overdue invoice",
        "payment due",
        "outstanding invoice",
        "invoice is attached",
    ],
    "credential_harvesting": [
        "verify your password",
        "confirm your credentials",
        "login to verify",
        "reset your password immediately",
        "update your payment information",
    ],
    "executive_impersonation": [
        "on behalf of the ceo",
        "urgent request from ceo",
        "confidential request",
        "are you at your desk",
        "handle a task for me",
    ],
}

SUSPICIOUS_ATTACHMENT_EXTENSIONS: list[str] = [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".jar",
    ".hta",
    ".ps1",
]

# TLDs disproportionately used for abuse/phishing infrastructure (hackathon-scope
# reference list, not exhaustive — tune freely).
SUSPICIOUS_TLDS: list[str] = [
    "zip",
    "xyz",
    "top",
    "click",
    "work",
    "gq",
    "tk",
    "ml",
    "cf",
    "loan",
    "download",
]

URL_SHORTENER_DOMAINS: list[str] = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
]

MAX_SUBDOMAIN_COUNT = 3  # more labels than this before the registered domain -> flagged


def build_signal(name: str, evidence: str, score_override: int | None = None) -> dict:
    """Shared by detection_engine.py and url_analysis_service.py so every signal —
    wherever it's raised from — has exactly one construction path."""
    definition = SIGNAL_DEFINITIONS[name]
    return {
        "name": name,
        "category": definition["category"],
        "severity": definition["severity"],
        "score": score_override if score_override is not None else definition["score"],
        "explanation": definition["explanation"],
        "evidence": evidence,
    }
