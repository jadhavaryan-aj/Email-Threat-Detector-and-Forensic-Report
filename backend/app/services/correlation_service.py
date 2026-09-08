"""PS component 4: cross-case correlation via shared IP/domain infrastructure. No
generic graph database — just queries over IndicatorObservation (one row per IP/domain
seen per case). Always phrased as "potential correlation" / "shared infrastructure",
never "same attacker" — see PS section 13/27."""

from sqlmodel import Session, select

from app.models.case import Case, DetectionResult, EmailAnalysis, HeaderAuthResult
from app.models.correlation import IndicatorObservation
from app.models.intelligence import IpIntelligence
from app.models.signal import Signal

# PS component 4: "confidence-scored attribution" — deliberately a rule-based
# classifier over signals/intelligence already computed elsewhere, not a new ML
# model, matching the rest of this codebase's explainable-over-opaque scoring.
# These four scenarios are broad DFIR attribution categories, not a claim that
# the actual attacker's identity or physical location has been established.
_IDENTITY_SPOOF_SIGNALS = {
    "lookalike_domain_match",
    "display_name_impersonation",
    "reply_to_domain_mismatch",
    "return_path_domain_mismatch",
}
_SOCIAL_ENGINEERING_SIGNALS = {
    "urgency",
    "payment_diversion",
    "fake_invoice",
    "credential_harvesting",
    "executive_impersonation",
}
_MIN_SCORE_FOR_ATTRIBUTION = 40  # start of the "impersonated" band — see scoring_config.CLASSIFICATION_BANDS


def find_shared_infrastructure(session: Session, case_id: int) -> list[dict]:
    """For every indicator (IP/domain) observed in this case, find which *other* cases
    also observed it."""
    this_case_indicators = session.exec(
        select(IndicatorObservation.indicator_type, IndicatorObservation.indicator_value)
        .where(IndicatorObservation.case_id == case_id)
        .distinct()
    ).all()

    shared = []
    for indicator_type, indicator_value in this_case_indicators:
        other_case_ids = session.exec(
            select(IndicatorObservation.case_id)
            .where(
                IndicatorObservation.indicator_type == indicator_type,
                IndicatorObservation.indicator_value == indicator_value,
                IndicatorObservation.case_id != case_id,
            )
            .distinct()
        ).all()
        if other_case_ids:
            shared.append(
                {
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "other_case_ids": sorted(set(other_case_ids)),
                    "note": "Potential shared infrastructure detected — this does not confirm the same actor.",
                }
            )
    return shared


def build_case_graph(session: Session, case_id: int) -> dict:
    """Nodes/edges for the frontend correlation graph: this case's own indicator
    nodes, plus edges out to *other* cases that share one of those indicators."""
    if session.get(Case, case_id) is None:
        return {"nodes": [], "edges": []}

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, node_type: str, label: str) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label})

    case_node_id = f"case:{case_id}"
    add_node(case_node_id, "case", f"Case #{case_id}")

    observations = session.exec(select(IndicatorObservation).where(IndicatorObservation.case_id == case_id)).all()

    for obs in observations:
        indicator_node_id = f"{obs.indicator_type}:{obs.indicator_value}"
        add_node(indicator_node_id, obs.indicator_type, obs.indicator_value)
        edges.append({"source": case_node_id, "target": indicator_node_id, "relationship": "observed_in"})

        other_case_ids = session.exec(
            select(IndicatorObservation.case_id)
            .where(
                IndicatorObservation.indicator_type == obs.indicator_type,
                IndicatorObservation.indicator_value == obs.indicator_value,
                IndicatorObservation.case_id != case_id,
            )
            .distinct()
        ).all()
        for other_case_id in set(other_case_ids):
            other_node_id = f"case:{other_case_id}"
            add_node(other_node_id, "case", f"Case #{other_case_id}")
            edges.append(
                {"source": indicator_node_id, "target": other_node_id, "relationship": "potential_correlation"}
            )

    return {"nodes": list(nodes.values()), "edges": edges}


def assess_attribution_scenario(session: Session, case_id: int) -> dict:
    """Classifies this case into one of four broad DFIR attribution scenarios,
    purely from signals/intelligence already computed during ingestion. Always
    a hypothesis with stated evidence and a confidence, never a claim of a
    confirmed attacker identity or location (see PS section 13/27)."""
    if session.get(Case, case_id) is None:
        return {"scenario": "insufficient_data", "confidence": 0.0, "reasoning": "Case not found."}

    analyses = session.exec(select(EmailAnalysis).where(EmailAnalysis.case_id == case_id)).all()
    if not analyses:
        return {"scenario": "insufficient_data", "confidence": 0.0, "reasoning": "No analyzed emails in this case."}

    # Attribute based on the single riskiest email in the case — attribution is
    # a property of one message's origin, and averaging across a mixed case
    # would blur that.
    scored = []
    for email in analyses:
        detection = session.exec(select(DetectionResult).where(DetectionResult.email_analysis_id == email.id)).first()
        scored.append((detection.fraud_score if detection else -1, email, detection))
    scored.sort(key=lambda t: t[0], reverse=True)
    fraud_score, email, detection = scored[0]

    if detection is None or fraud_score < _MIN_SCORE_FOR_ATTRIBUTION:
        return {
            "scenario": "insufficient_data",
            "confidence": 0.0,
            "reasoning": "Risk score is too low to support an attribution assessment.",
        }

    header = session.exec(select(HeaderAuthResult).where(HeaderAuthResult.email_analysis_id == email.id)).first()
    signal_names = {
        s.name for s in session.exec(select(Signal).where(Signal.email_analysis_id == email.id)).all()
    }
    ip_intel = session.exec(select(IpIntelligence).where(IpIntelligence.email_analysis_id == email.id)).first()
    shared_ip_infra = [row for row in find_shared_infrastructure(session, case_id) if row["indicator_type"] == "ip"]

    # 1. Anonymized infrastructure — the origin itself is designed to not point
    #    back to a fixed, attributable source.
    if ip_intel and ip_intel.available and ip_intel.is_vpn_or_proxy_or_tor:
        reasoning = [f"Originating IP {ip_intel.ip} is flagged as VPN/proxy/Tor exit infrastructure."]
        confidence = 0.55
        if shared_ip_infra:
            reasoning.append(f"This IP is also observed in case(s) {shared_ip_infra[0]['other_case_ids']}.")
            confidence = 0.75
        return {"scenario": "anonymized_infrastructure", "confidence": confidence, "reasoning": " ".join(reasoning)}

    if shared_ip_infra and "ip_reputation_flagged" in signal_names:
        return {
            "scenario": "anonymized_infrastructure",
            "confidence": 0.6,
            "reasoning": (
                f"Sending IP is independently flagged as malicious and also observed across "
                f"case(s) {shared_ip_infra[0]['other_case_ids']}, consistent with shared attack "
                f"infrastructure rather than one dedicated origin."
            ),
        }

    identity_spoof_hits = signal_names & _IDENTITY_SPOOF_SIGNALS
    social_engineering_hits = signal_names & _SOCIAL_ENGINEERING_SIGNALS
    auth_clean = bool(
        header
        and header.spf_result == "pass"
        and header.dkim_result == "pass"
        and header.dmarc_result == "pass"
        and header.spf_aligned
        and header.dkim_aligned
    )

    # 2. Compromised account — authentication genuinely passes and aligns (the
    #    message really did come from the claimed domain's own infrastructure),
    #    yet the content still looks fraudulent. That combination points at a
    #    hijacked mailbox, not a forged sender.
    if auth_clean and social_engineering_hits and not identity_spoof_hits:
        return {
            "scenario": "compromised_account",
            "confidence": 0.65,
            "reasoning": (
                "SPF, DKIM, and DMARC all pass and align to the visible sending domain, so the "
                "message genuinely originated from that domain's authorized infrastructure. "
                f"However, content analysis flagged: {', '.join(sorted(social_engineering_hits))} — "
                "patterns more consistent with a hijacked mailbox than a forged sender."
            ),
        }

    # 3. Spoofed domain — the visible sender identity itself is fabricated or
    #    doesn't align with who actually sent the message.
    auth_misaligned = bool(
        header and (not header.spf_aligned or not header.dkim_aligned) and header.dmarc_result == "fail"
    )
    if identity_spoof_hits or auth_misaligned:
        reasoning = []
        if identity_spoof_hits:
            reasoning.append(f"Identity-spoofing signals present: {', '.join(sorted(identity_spoof_hits))}.")
        if header:
            reasoning.append(
                f"Authentication does not align to the visible From: domain "
                f"(SPF={header.spf_result}, DKIM={header.dkim_result}, DMARC={header.dmarc_result})."
            )
        return {
            "scenario": "spoofed_domain",
            "confidence": 0.75 if identity_spoof_hits else 0.55,
            "reasoning": " ".join(reasoning),
        }

    # 4. Fallback — still a genuinely risky email, but without the specific
    #    spoofing/compromise/anonymization patterns above: the most defensible
    #    read is a directly-sent message from whatever origin was observed.
    reasoning = [
        f"Classified as {detection.threat_category} (score {fraud_score}/100) without strong indicators of "
        "domain spoofing, account compromise, or anonymized infrastructure."
    ]
    if ip_intel and ip_intel.available:
        location = ", ".join(filter(None, [ip_intel.city, ip_intel.region, ip_intel.country]))
        reasoning.append(
            f"The observed origin ({ip_intel.ip}{f', {location}' if location else ''}) appears to be a "
            "direct, non-anonymized source."
        )
    return {"scenario": "direct_actor", "confidence": 0.4, "reasoning": " ".join(reasoning)}
