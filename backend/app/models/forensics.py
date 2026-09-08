from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CaseNote(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)

    author: str = "analyst"
    note_text: str
    created_at: datetime = Field(default_factory=_utcnow)


class TimelineEvent(SQLModel, table=True):
    """PS component 5: forensic investigation timeline."""

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    email_analysis_id: Optional[int] = Field(default=None, foreign_key="emailanalysis.id")

    event_type: str
    description: str
    occurred_at: datetime = Field(default_factory=_utcnow)


class EvidenceLogEntry(SQLModel, table=True):
    """PS privacy/compliance component: tamper-evident, hash-chained,
    append-only chain of custody — one chain per case. entry_hash covers
    prev_entry_hash + payload, so an edited row breaks its own hash and every
    entry chained after it; see app/utils/hash_chain.py for the actual check."""

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    email_analysis_id: Optional[int] = Field(default=None, foreign_key="emailanalysis.id")

    action: str  # ingested | analyzed | report_exported | viewed
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    prev_entry_hash: str
    entry_hash: str
    created_at: datetime = Field(default_factory=_utcnow)
