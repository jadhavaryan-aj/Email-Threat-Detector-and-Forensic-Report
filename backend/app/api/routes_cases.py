from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.db import get_session
from app.models.case import Case, DetectionResult, EmailAnalysis, HeaderAuthResult
from app.models.forensics import CaseNote, TimelineEvent
from app.models.intelligence import DomainIntelligence, ExtractedUrl, IpIntelligence, ThreatIntelResult
from app.models.signal import Signal
from app.services import evidence_log_service

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
def list_cases(min_score: int | None = None, session: Session = Depends(get_session)):
    query = (
        select(EmailAnalysis, DetectionResult, Case)
        .join(DetectionResult, DetectionResult.email_analysis_id == EmailAnalysis.id)
        .join(Case, Case.id == EmailAnalysis.case_id)
        .order_by(EmailAnalysis.created_at.desc())
    )
    if min_score is not None:
        query = query.where(DetectionResult.fraud_score >= min_score)
    rows = session.exec(query).all()

    return [
        {
            "case_id": case.id,
            "email_analysis_id": email.id,
            "subject": email.subject,
            "from_address": email.from_address,
            "fraud_score": detection.fraud_score,
            "classification_label": detection.classification_label,
            "threat_category": detection.threat_category,
            "status": case.status,
            "source_url": email.source_url,
            "created_at": email.created_at.isoformat(),
        }
        for email, detection, case in rows
    ]


@router.get("/{case_id}")
def get_case(case_id: int, session: Session = Depends(get_session)):
    case = session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    analyses = session.exec(select(EmailAnalysis).where(EmailAnalysis.case_id == case_id)).all()

    email_payload = []
    for email in analyses:
        header = session.exec(
            select(HeaderAuthResult).where(HeaderAuthResult.email_analysis_id == email.id)
        ).first()
        detection = session.exec(
            select(DetectionResult).where(DetectionResult.email_analysis_id == email.id)
        ).first()
        signals = session.exec(select(Signal).where(Signal.email_analysis_id == email.id)).all()
        urls = session.exec(select(ExtractedUrl).where(ExtractedUrl.email_analysis_id == email.id)).all()
        domain_intel = session.exec(
            select(DomainIntelligence).where(DomainIntelligence.email_analysis_id == email.id)
        ).all()
        ip_intel = session.exec(select(IpIntelligence).where(IpIntelligence.email_analysis_id == email.id)).all()
        threat_intel = session.exec(
            select(ThreatIntelResult).where(ThreatIntelResult.email_analysis_id == email.id)
        ).all()

        email_payload.append(
            {
                "id": email.id,
                "original_filename": email.original_filename,
                "source_url": email.source_url,
                "subject": email.subject,
                "from_display_name": email.from_display_name,
                "from_address": email.from_address,
                "reply_to": email.reply_to,
                "return_path": email.return_path,
                "to_addresses": email.to_addresses,
                "cc_addresses": email.cc_addresses,
                "date_header": email.date_header,
                "message_id": email.message_id,
                "authentication_results": email.authentication_results,
                "mime_structure": email.mime_structure,
                "body_text": email.body_text,
                "attachments": email.attachments,
                "raw_eml_sha256": email.raw_eml_sha256,
                "created_at": email.created_at.isoformat(),
                "header_auth_result": header.model_dump() if header else None,
                "detection_result": detection.model_dump() if detection else None,
                "signals": [s.model_dump() for s in signals],
                "extracted_urls": [u.model_dump() for u in urls],
                "domain_intelligence": [d.model_dump() for d in domain_intel],
                "ip_intelligence": [i.model_dump() for i in ip_intel],
                "threat_intel_results": [t.model_dump() for t in threat_intel],
            }
        )

    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "overall_risk_level": case.overall_risk_level,
        "created_at": case.created_at.isoformat(),
        "email_analyses": email_payload,
    }


@router.get("/{case_id}/timeline")
def get_case_timeline(case_id: int, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")

    events = session.exec(
        select(TimelineEvent).where(TimelineEvent.case_id == case_id).order_by(TimelineEvent.occurred_at)
    ).all()
    return [e.model_dump() for e in events]


@router.get("/{case_id}/evidence-log")
def get_case_evidence_log(case_id: int, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")

    chain = evidence_log_service.get_chain_with_verification(session, case_id)
    return {
        "valid": chain["valid"],
        "first_broken_index": chain["first_broken_index"],
        "entries": [e.model_dump() for e in chain["entries"]],
    }


class CaseNoteCreate(BaseModel):
    note_text: str
    author: str = "analyst"


@router.post("/{case_id}/notes")
def add_case_note(case_id: int, payload: CaseNoteCreate, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if not payload.note_text.strip():
        raise HTTPException(status_code=400, detail="note_text cannot be empty")

    note = CaseNote(case_id=case_id, author=payload.author, note_text=payload.note_text.strip())
    session.add(note)
    session.add(
        TimelineEvent(
            case_id=case_id,
            event_type="note_added",
            description=f"{payload.author} added a note",
        )
    )
    session.commit()
    session.refresh(note)
    return note.model_dump()


@router.get("/{case_id}/notes")
def list_case_notes(case_id: int, session: Session = Depends(get_session)):
    if session.get(Case, case_id) is None:
        raise HTTPException(status_code=404, detail="Case not found")
    notes = session.exec(
        select(CaseNote).where(CaseNote.case_id == case_id).order_by(CaseNote.created_at)
    ).all()
    return [n.model_dump() for n in notes]


_VALID_STATUSES = {"new", "investigating", "escalated", "resolved", "false_positive"}


class CaseStatusUpdate(BaseModel):
    status: str


@router.patch("/{case_id}/status")
def update_case_status(case_id: int, payload: CaseStatusUpdate, session: Session = Depends(get_session)):
    case = session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if payload.status not in _VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(_VALID_STATUSES)}")

    previous_status = case.status
    case.status = payload.status
    session.add(case)
    session.add(
        TimelineEvent(
            case_id=case_id,
            event_type="status_changed",
            description=f"Status changed from '{previous_status}' to '{payload.status}'",
        )
    )
    session.commit()
    session.refresh(case)
    return case.model_dump()
