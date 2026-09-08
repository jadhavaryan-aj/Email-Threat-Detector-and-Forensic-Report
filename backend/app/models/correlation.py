from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IndicatorObservation(SQLModel, table=True):
    """PS component 4: one row per IP/domain observed in a case — the substrate for
    cross-case correlation (GROUP BY indicator_value HAVING COUNT(DISTINCT case_id) > 1)
    without needing a generic graph database."""

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id", index=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    indicator_type: str  # "ip" | "domain"
    indicator_value: str = Field(index=True)
    observed_at: datetime = Field(default_factory=_utcnow)
