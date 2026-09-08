"""Generates the 3 demo .eml fixtures from real, DNS-verified ground truth
(see README.md in this folder for the exact DNS records these rely on, checked
2026-09-06). Re-run after editing this file to regenerate the fixtures:

    python generate_fixtures.py
"""

import base64
from email.message import EmailMessage
from pathlib import Path

OUT_DIR = Path(__file__).parent


def _write(msg: EmailMessage, filename: str) -> None:
    (OUT_DIR / filename).write_bytes(bytes(msg))
    print(f"wrote {filename}")


def build_clean_legit() -> EmailMessage:
    msg = EmailMessage()
    # Recipient-side hop first (most recent), origin hop last — matches real
    # header stacking order, and our parser reads Received headers top-to-bottom
    # as most-recent-first.
    msg.add_header(
        "Received",
        "from mx.example-recipient.org (localhost [127.0.0.1]) "
        "by mx.example-recipient.org with ESMTP id ab29f8k2 "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 10:16:00 +0000",
    )
    msg.add_header(
        "Received",
        # 74.125.20.41 is a real address inside Google's published SPF range
        # (_spf.google.com -> ip4:74.125.0.0/16) - a genuine SPF PASS, not a fake one.
        "from mail-sor-f41.google.com (mail-sor-f41.google.com [74.125.20.41]) "
        "by mx.example-recipient.org with SMTPS id xz881mc0 "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 10:15:45 +0000",
    )
    msg["Message-ID"] = "<CADx7fQ2rT9kLmN3vJpQzR8s@mail.gmail.com>"
    msg["Date"] = "Sun, 06 Sep 2026 10:15:40 +0000"
    msg["From"] = "Alex Mentor <alex.mentor@gmail.com>"
    msg["To"] = "Priya Sharma <priya.sharma@example-recipient.org>"
    msg["Subject"] = "Re: Mentorship session this Thursday"
    msg["Return-Path"] = "<alex.mentor@gmail.com>"
    msg.set_content(
        "Hi Priya,\n\n"
        "Thanks for confirming - Thursday at 4pm works well for me. I will send "
        "over the review notes for your prototype beforehand so we can go through "
        "them together on the call.\n\n"
        "Talk soon,\nAlex\n"
    )
    return msg


def build_spf_fail_spoofed() -> EmailMessage:
    msg = EmailMessage()
    msg.add_header(
        "Received",
        "from mx.example-recipient.org (localhost [127.0.0.1]) "
        "by mx.example-recipient.org with ESMTP id 7q3mv0aa "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 03:42:10 +0000",
    )
    msg.add_header(
        "Received",
        # 1.1.1.1 (Cloudflare public DNS) is a real, globally-routable address
        # that is NOT in sbi.co.in's published SPF ranges -> genuine hard SPF fail
        # against their real "-all" policy, not a fabricated result.
        "from vps-198231.hostingcloud.net (unknown [1.1.1.1]) "
        "by mx.example-recipient.org with SMTP id 9h2kx7bd "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 03:41:55 +0000",
    )
    msg["Message-ID"] = "<8f2ac910-secure-alert@sbi.co.in>"
    msg["Date"] = "Sun, 06 Sep 2026 03:41:50 +0000"
    msg["From"] = "State Bank of India Security <security-alerts@sbi.co.in>"
    msg["Reply-To"] = "SBI Verification Support <sbi.verify.support@protonmail.com>"
    msg["To"] = "Priya Sharma <priya.sharma@example-recipient.org>"
    msg["Subject"] = "URGENT: Your SBI Account Will Be Suspended - Verify Now"
    msg["Return-Path"] = "<security-alerts@sbi.co.in>"
    msg.set_content(
        "Dear Valued Customer,\n\n"
        "We have detected unusual activity on your SBI account. Your account "
        "will be locked within 24 hours unless you verify your account "
        "immediately.\n\n"
        "Please click here to confirm your identity and reset your password "
        "immediately: hxxp://sbi-online-verify[.]net/kyc-update\n\n"
        "Failure to act now will result in permanent suspension of your account.\n\n"
        "SBI Security Team\n"
    )
    return msg


def build_dmarc_fail_lookalike_bec() -> EmailMessage:
    msg = EmailMessage()
    msg.add_header(
        "Received",
        "from mx.example-recipient.org (localhost [127.0.0.1]) "
        "by mx.example-recipient.org with ESMTP id 4kd82jbb "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 14:05:33 +0000",
    )
    msg.add_header(
        "Received",
        # paypa1-secure-verification.com has zero DNS presence (confirmed
        # NXDOMAIN on A/TXT/MX, 2026-09-06) - SPF/DMARC genuinely evaluate to
        # "none", not a fabricated result. 8.8.8.8 is just a real public IP
        # placeholder for the relay; it plays no role once the domain itself
        # doesn't resolve.
        "from mail.paypa1-secure-verification.com (unknown [8.8.8.8]) "
        "by mx.example-recipient.org with SMTP id 2xa91mnc "
        "for <priya.sharma@example-recipient.org>; "
        "Sun, 06 Sep 2026 14:05:10 +0000",
    )
    msg["Message-ID"] = "<inv-2026-0906-billing@paypa1-secure-verification.com>"
    msg["Date"] = "Sun, 06 Sep 2026 14:05:00 +0000"
    msg["From"] = "PayPal Billing Support <billing@paypa1-secure-verification.com>"
    msg["To"] = "Priya Sharma <priya.sharma@example-recipient.org>"
    msg["Subject"] = "Action Required: Overdue Invoice and Updated Payment Instructions"
    msg["Return-Path"] = "<billing@paypa1-secure-verification.com>"
    msg.set_content(
        "Dear Priya,\n\n"
        "This is an urgent request from CEO - please handle a task for me "
        "confidentially before end of day.\n\n"
        "Please find the overdue invoice attached. Payment due within 24 hours. "
        "Kindly update your bank details and use the new account details below "
        "for this and all future payments to avoid any delay:\n\n"
        "Beneficiary Account: 000123456789\n"
        "Routing Number: 026073150\n\n"
        "Please confirm once the wire transfer has been sent.\n\n"
        "Regards,\nBilling Department\nPayPal Billing Support\n"
    )
    msg.add_attachment(
        base64.b64decode("Ly8gVGVzdCBmaXh0dXJlIG9ubHkgLSBub3QgcmVhbCBleGVjdXRhYmxlIGNvbnRlbnQu"),
        maintype="application",
        subtype="octet-stream",
        filename="Payment_Instructions.js",
    )
    return msg


if __name__ == "__main__":
    _write(build_clean_legit(), "clean_legit_001.eml")
    _write(build_spf_fail_spoofed(), "spf_fail_spoofed_001.eml")
    _write(build_dmarc_fail_lookalike_bec(), "dmarc_fail_lookalike_bec_001.eml")
