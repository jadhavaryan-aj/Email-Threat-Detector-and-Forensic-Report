"""Orchestrates the full investigation pipeline for one uploaded .eml file:
parse -> header/auth analysis -> URL analysis -> domain/IP/threat intelligence ->
signal-based scoring -> persistence -> indicator observations (for correlation) ->
timeline events. Every external-call stage (WHOIS/DNS reputation/ip-api/threat-intel)
is wrapped by the providers themselves (see app/intelligence/) so a network failure
degrades that one piece of intelligence to "unavailable" and never aborts ingestion."""

from sqlmodel import Session

from app.config import settings
from app.intelligence.env_threat_intel_provider import EnvThreatIntelligenceProvider
from app.intelligence.local_domain_provider import LocalDomainIntelligenceProvider
from app.intelligence.local_ip_provider import LocalIpIntelligenceProvider
from app.models.case import Case, DetectionResult, EmailAnalysis, HeaderAuthResult
from app.models.correlation import IndicatorObservation
from app.models.forensics import TimelineEvent
from app.models.intelligence import DomainIntelligence, ExtractedUrl, IpIntelligence
from app.models.intelligence import ThreatIntelResult as ThreatIntelResultRow
from app.models.signal import Signal
from app.services import detection_engine, evidence_log_service, header_protocol_service, url_analysis_service
from app.services.scoring_config import build_signal
from app.utils.domain_similarity import registrable_label
from app.utils.eml_parser import parse_eml_bytes, sha256_hex

_RISK_ORDER = ["legitimate", "suspicious", "impersonated", "phishing", "fraud"]

_domain_provider = LocalDomainIntelligenceProvider()
_ip_provider = LocalIpIntelligenceProvider()
_threat_provider = EnvThreatIntelligenceProvider()


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if address and "@" in address else ""


def _log_event(session: Session, case_id: int, email_analysis_id: int | None, event_type: str, description: str) -> None:
    session.add(
        TimelineEvent(
            case_id=case_id, email_analysis_id=email_analysis_id, event_type=event_type, description=description
        )
    )


def ingest_email(
    session: Session, raw_bytes: bytes, filename: str, case_id: int | None = None, source_url: str = ""
) -> EmailAnalysis:
    parsed = parse_eml_bytes(raw_bytes)
    file_hash = sha256_hex(raw_bytes)

    raw_path = settings.raw_email_path / f"{file_hash}.eml"
    if not raw_path.exists():
        raw_path.write_bytes(raw_bytes)

    if case_id is None:
        case = Case(title=parsed["subject"] or filename)
        session.add(case)
        session.flush()
        case_id = case.id
    _log_event(session, case_id, None, "ingested", f"Uploaded '{filename}' (sha256 {file_hash[:12]}...)")

    # --- header / auth analysis (PS component 2) ---
    header_analysis = header_protocol_service.analyze_headers(parsed)
    signals = detection_engine.generate_signals(parsed, header_analysis)
    _log_event(
        session,
        case_id,
        None,
        "headers_analyzed",
        f"SPF={header_analysis['spf_result']}, DKIM={header_analysis['dkim_result']}, "
        f"DMARC={header_analysis['dmarc_result']}",
    )

    # --- URL analysis (PS component 1/9) ---
    url_rows, url_signals = url_analysis_service.analyze_urls(parsed["urls"])
    signals.extend(url_signals)
    _log_event(session, case_id, None, "urls_extracted", f"{len(url_rows)} URL(s) found and analyzed")

    # --- domain / IP / threat intelligence (PS component 3/12) ---
    from_domain = _domain_of(parsed["from_address"])
    originating_ip = header_analysis.get("originating_ip")

    domains_to_check = {from_domain} if from_domain else set()
    domains_to_check |= {row["registered_domain"] for row in url_rows if row["registered_domain"]}

    domain_intel_rows = [_domain_provider.lookup(domain) for domain in domains_to_check]
    ip_intel_row = _ip_provider.lookup(originating_ip) if originating_ip else None
    threat_ip_result = _threat_provider.check_ip(originating_ip) if originating_ip else None
    threat_domain_result = _threat_provider.check_domain(from_domain) if from_domain else None
    _log_event(
        session,
        case_id,
        None,
        "intelligence_retrieved",
        f"Domain intel: {len(domain_intel_rows)} domain(s); "
        f"IP intel: {'available' if ip_intel_row and ip_intel_row.available else 'unavailable'}; "
        f"Threat intel: {'configured' if settings.abuseipdb_api_key or settings.virustotal_api_key else 'no API key configured'}",
    )

    # --- reputation signals derived from the intelligence just gathered ---
    ip_flagged_by = []
    if ip_intel_row and ip_intel_row.dnsbl_listed:
        ip_flagged_by.append("Spamhaus ZEN")
    if threat_ip_result and threat_ip_result.available and threat_ip_result.verdict == "malicious":
        ip_flagged_by.append(threat_ip_result.provider)
    if ip_flagged_by:
        signals.append(
            build_signal("ip_reputation_flagged", f"{originating_ip} flagged by: {', '.join(ip_flagged_by)}")
        )

    domain_flagged_by = []
    sender_domain_intel = next((d for d in domain_intel_rows if d.domain == from_domain), None)
    if sender_domain_intel and sender_domain_intel.dnsbl_listed:
        domain_flagged_by.append("Spamhaus DBL")
    if threat_domain_result and threat_domain_result.available and threat_domain_result.verdict == "malicious":
        domain_flagged_by.append(threat_domain_result.provider)
    if domain_flagged_by:
        signals.append(
            build_signal("domain_reputation_flagged", f"{from_domain} flagged by: {', '.join(domain_flagged_by)}")
        )

    # --- scoring & classification (PS component 1) ---
    fraud_score = detection_engine.score_signals(signals)
    classification_label = detection_engine.classify_risk_band(fraud_score)
    threat_category, secondary_indicators = detection_engine.classify_threat_category(signals, fraud_score)
    _log_event(
        session,
        case_id,
        None,
        "risk_scored",
        f"{classification_label} ({fraud_score}/100), primary category: {threat_category}",
    )

    # --- persistence ---
    email_analysis = EmailAnalysis(
        case_id=case_id,
        raw_eml_path=str(raw_path),
        raw_eml_sha256=file_hash,
        original_filename=filename,
        source_url=source_url,
        subject=parsed["subject"],
        from_display_name=parsed["from_display_name"],
        from_address=parsed["from_address"],
        reply_to=parsed["reply_to"],
        return_path=parsed["return_path"],
        to_addresses=parsed["to_addresses"],
        cc_addresses=parsed["cc_addresses"],
        date_header=parsed["date_header"],
        message_id=parsed["message_id"],
        raw_headers=parsed["headers"],
        authentication_results=parsed["authentication_results"],
        mime_structure=parsed["mime_structure"],
        body_text=parsed["body_text"],
        body_html=parsed["body_html"],
        attachments=parsed["attachments"],
    )
    session.add(email_analysis)
    session.flush()
    email_analysis_id = email_analysis.id

    evidence_log_service.append_entry(
        session,
        case_id,
        "ingested",
        {"filename": filename, "sha256": file_hash, "source_url": source_url},
        email_analysis_id=email_analysis_id,
    )
    evidence_log_service.append_entry(
        session,
        case_id,
        "analyzed",
        {
            "classification_label": classification_label,
            "fraud_score": fraud_score,
            "threat_category": threat_category,
            "signal_count": len(signals),
        },
        email_analysis_id=email_analysis_id,
    )

    session.add(
        HeaderAuthResult(
            email_analysis_id=email_analysis_id,
            spf_result=header_analysis["spf_result"],
            spf_domain=header_analysis["spf_domain"],
            dkim_result=header_analysis["dkim_result"],
            dkim_domain=header_analysis["dkim_domain"],
            dmarc_result=header_analysis["dmarc_result"],
            dmarc_policy=header_analysis["dmarc_policy"],
            spf_aligned=header_analysis["spf_aligned"],
            dkim_aligned=header_analysis["dkim_aligned"],
            routing_anomaly_flags=header_analysis["routing_anomaly_flags"],
            received_chain=header_analysis["received_chain"],
            auth_cross_check=header_analysis["auth_cross_check"],
        )
    )

    session.add(
        DetectionResult(
            email_analysis_id=email_analysis_id,
            classification_label=classification_label,
            fraud_score=fraud_score,
            threat_category=threat_category,
            secondary_indicators=secondary_indicators,
        )
    )

    for sig in signals:
        session.add(Signal(email_analysis_id=email_analysis_id, **sig))

    for row in url_rows:
        session.add(ExtractedUrl(email_analysis_id=email_analysis_id, **row))

    for domain_intel in domain_intel_rows:
        session.add(
            DomainIntelligence(
                email_analysis_id=email_analysis_id,
                domain=domain_intel.domain,
                registered_domain=domain_intel.registered_domain,
                tld=domain_intel.tld,
                mx_records=domain_intel.mx_records,
                nameservers=domain_intel.nameservers,
                registrar=domain_intel.registrar,
                created_date=domain_intel.created_date,
                age_days=domain_intel.age_days,
                dnsbl_listed=domain_intel.dnsbl_listed,
                source=domain_intel.source,
                available=domain_intel.available,
                unavailable_reason=domain_intel.unavailable_reason,
            )
        )
        session.add(
            IndicatorObservation(
                case_id=case_id,
                email_analysis_id=email_analysis_id,
                indicator_type="domain",
                indicator_value=domain_intel.domain,
            )
        )

    if ip_intel_row:
        session.add(
            IpIntelligence(
                email_analysis_id=email_analysis_id,
                ip=ip_intel_row.ip,
                ip_version=ip_intel_row.ip_version,
                is_public=ip_intel_row.is_public,
                asn=ip_intel_row.asn,
                asn_org=ip_intel_row.asn_org,
                country=ip_intel_row.country,
                region=ip_intel_row.region,
                city=ip_intel_row.city,
                isp_org=ip_intel_row.isp_org,
                is_vpn_or_proxy_or_tor=ip_intel_row.is_vpn_or_proxy_or_tor,
                dnsbl_listed=ip_intel_row.dnsbl_listed,
                source=ip_intel_row.source,
                available=ip_intel_row.available,
                unavailable_reason=ip_intel_row.unavailable_reason,
                disclaimer=ip_intel_row.disclaimer,
            )
        )
        session.add(
            IndicatorObservation(
                case_id=case_id,
                email_analysis_id=email_analysis_id,
                indicator_type="ip",
                indicator_value=ip_intel_row.ip,
            )
        )

    for threat_result in (threat_ip_result, threat_domain_result):
        if threat_result:
            session.add(
                ThreatIntelResultRow(
                    email_analysis_id=email_analysis_id,
                    provider=threat_result.provider,
                    indicator_type=threat_result.indicator_type,
                    indicator_value=threat_result.indicator_value,
                    available=threat_result.available,
                    verdict=threat_result.verdict,
                    raw_response=threat_result.raw_response,
                )
            )

    case = session.get(Case, case_id)
    current_rank = _RISK_ORDER.index(case.overall_risk_level) if case.overall_risk_level in _RISK_ORDER else -1
    new_rank = _RISK_ORDER.index(classification_label)
    if new_rank >= current_rank:
        case.overall_risk_level = classification_label
        session.add(case)

    session.commit()
    session.refresh(email_analysis)
    return email_analysis
