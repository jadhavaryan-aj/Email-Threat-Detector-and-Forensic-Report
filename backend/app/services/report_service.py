"""PS component 5/16: forensic PDF report generation via xhtml2pdf + Jinja2 (pure
Python, no native Windows dependency chain — see docs/build_roadmap.md for why
WeasyPrint was rejected)."""

import io
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from sqlmodel import Session, select
from xhtml2pdf import pisa

from app.models.case import Case, DetectionResult, EmailAnalysis, HeaderAuthResult
from app.models.forensics import CaseNote, TimelineEvent
from app.models.intelligence import DomainIntelligence, ExtractedUrl, IpIntelligence, ThreatIntelResult
from app.models.signal import Signal
from app.services.correlation_service import find_shared_infrastructure
from app.services.evidence_log_service import get_chain_with_verification

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
# autoescape=True is load-bearing, not a default-safe choice: every value rendered
# here (subject, from_display_name, note text, URLs, ...) originates from an
# untrusted .eml. Without escaping, a crafted Subject like '<img src="file:///...">'
# would be interpreted as real HTML by xhtml2pdf, which does fetch image sources —
# a stored injection/SSRF path into report generation, not just a cosmetic issue.
_env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
# xhtml2pdf/reportlab doesn't reliably honor CSS word-break on long unbroken strings
# (the SHA-256 hash was visually clipping in its table cell) — space-chunking gives
# the renderer real wrap points without changing the underlying value.
_env.filters["chunked"] = lambda value, size=8: " ".join(value[i : i + size] for i in range(0, len(value), size))


def _collect_email_block(session: Session, email: EmailAnalysis) -> dict:
    signals = session.exec(select(Signal).where(Signal.email_analysis_id == email.id)).all()
    return {
        "email": email,
        "header": session.exec(
            select(HeaderAuthResult).where(HeaderAuthResult.email_analysis_id == email.id)
        ).first(),
        "detection": session.exec(
            select(DetectionResult).where(DetectionResult.email_analysis_id == email.id)
        ).first(),
        "signals": sorted(signals, key=lambda s: s.score, reverse=True),
        "urls": session.exec(select(ExtractedUrl).where(ExtractedUrl.email_analysis_id == email.id)).all(),
        "domain_intel": session.exec(
            select(DomainIntelligence).where(DomainIntelligence.email_analysis_id == email.id)
        ).all(),
        "ip_intel": session.exec(select(IpIntelligence).where(IpIntelligence.email_analysis_id == email.id)).all(),
        "threat_intel": session.exec(
            select(ThreatIntelResult).where(ThreatIntelResult.email_analysis_id == email.id)
        ).all(),
    }


def generate_case_report_pdf(session: Session, case_id: int) -> bytes | None:
    case = session.get(Case, case_id)
    if case is None:
        return None

    analyses = session.exec(select(EmailAnalysis).where(EmailAnalysis.case_id == case_id)).all()
    email_blocks = [_collect_email_block(session, email) for email in analyses]

    notes = session.exec(select(CaseNote).where(CaseNote.case_id == case_id).order_by(CaseNote.created_at)).all()
    timeline = session.exec(
        select(TimelineEvent).where(TimelineEvent.case_id == case_id).order_by(TimelineEvent.occurred_at)
    ).all()
    shared_infra = find_shared_infrastructure(session, case_id)
    evidence_log = get_chain_with_verification(session, case_id)

    template = _env.get_template("forensic_report.html")
    html = template.render(
        case=case,
        email_blocks=email_blocks,
        notes=notes,
        timeline=timeline,
        shared_infra=shared_infra,
        evidence_log=evidence_log,
        generated_at=datetime.now(timezone.utc),
    )

    output = io.BytesIO()
    result = pisa.CreatePDF(io.StringIO(html), dest=output)
    if result.err:
        return None
    return output.getvalue()
