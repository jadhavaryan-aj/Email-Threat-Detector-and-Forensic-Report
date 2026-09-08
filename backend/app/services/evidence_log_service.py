"""Appends to and verifies each case's hash-chained evidence log. append_entry()
is the only way entries are created and always chains onto whatever the last
entry for that case currently is, so the log is append-only from the
application's perspective. get_chain_with_verification() recomputes the whole
chain from the stored payloads on every call — never a cached/trusted flag."""

from sqlmodel import Session, select

from app.models.forensics import EvidenceLogEntry
from app.utils.hash_chain import GENESIS_HASH, compute_entry_hash, verify_chain


def append_entry(
    session: Session,
    case_id: int,
    action: str,
    payload: dict,
    email_analysis_id: int | None = None,
) -> EvidenceLogEntry:
    last_entry = session.exec(
        select(EvidenceLogEntry)
        .where(EvidenceLogEntry.case_id == case_id)
        .order_by(EvidenceLogEntry.id.desc())
    ).first()
    prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH

    entry = EvidenceLogEntry(
        case_id=case_id,
        email_analysis_id=email_analysis_id,
        action=action,
        payload=payload,
        prev_entry_hash=prev_hash,
        entry_hash=compute_entry_hash(prev_hash, payload),
    )
    session.add(entry)
    return entry


def get_chain_with_verification(session: Session, case_id: int) -> dict:
    entries = session.exec(
        select(EvidenceLogEntry).where(EvidenceLogEntry.case_id == case_id).order_by(EvidenceLogEntry.id)
    ).all()

    valid, first_broken_index = verify_chain(
        [{"prev_entry_hash": e.prev_entry_hash, "entry_hash": e.entry_hash, "payload": e.payload} for e in entries]
    )

    return {
        "entries": entries,
        "valid": valid,
        "first_broken_index": first_broken_index,
    }
