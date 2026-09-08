import enum
from typing import Optional

from sqlmodel import Field, SQLModel


class SignalCategory(str, enum.Enum):
    authentication = "authentication"
    identity = "identity"
    content = "content"
    infrastructure = "infrastructure"
    reputation = "reputation"
    url = "url"


class SignalSeverity(str, enum.Enum):
    low = "LOW"
    medium = "MEDIUM"
    high = "HIGH"
    critical = "CRITICAL"


class Signal(SQLModel, table=True):
    """One structured, explainable risk signal — the atomic unit the risk score and
    the forensic report are built from. See scoring_config.SIGNAL_DEFINITIONS."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    name: str
    category: str
    severity: str
    score: int
    explanation: str
    evidence: str = ""
