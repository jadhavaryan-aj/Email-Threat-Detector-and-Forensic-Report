import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, Relationship, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ClassificationLabel(str, enum.Enum):
    """Matches the SIH26106 problem statement's own 5-way wording — this is the
    risk-band label graded against the PS, kept separate from ThreatCategory below."""

    legitimate = "legitimate"
    suspicious = "suspicious"
    impersonated = "impersonated"
    phishing = "phishing"
    fraud = "fraud"


class ThreatCategory(str, enum.Enum):
    """Investigator-facing threat taxonomy — a case can be risk-band 'fraud' *and*
    category 'business_email_compromise' at the same time; these answer different
    questions (how risky vs. what kind of attack)."""

    legitimate = "legitimate"
    spam = "spam"
    phishing = "phishing"
    spear_phishing = "spear_phishing"
    business_email_compromise = "business_email_compromise"
    spoofing = "spoofing"
    credential_theft = "credential_theft"
    malware_delivery = "malware_delivery"
    suspicious_unknown = "suspicious_unknown"


class CaseStatus(str, enum.Enum):
    new = "new"
    investigating = "investigating"
    escalated = "escalated"
    resolved = "resolved"
    false_positive = "false_positive"


class Case(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    status: str = CaseStatus.new.value
    overall_risk_level: str = "unknown"
    created_at: datetime = Field(default_factory=_utcnow)

    email_analyses: list["EmailAnalysis"] = Relationship(back_populates="case")


class EmailAnalysis(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: int = Field(foreign_key="case.id")

    raw_eml_path: str
    raw_eml_sha256: str
    original_filename: str = ""
    # Deep link back to the original message (e.g. a Gmail URL) — set by the
    # Chrome extension on upload; empty for manually-uploaded .eml files.
    source_url: str = ""

    subject: str = ""
    from_display_name: str = ""
    from_address: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addresses: list = Field(default_factory=list, sa_column=Column(JSON))
    cc_addresses: list = Field(default_factory=list, sa_column=Column(JSON))
    date_header: str = ""
    message_id: str = ""

    raw_headers: dict = Field(default_factory=dict, sa_column=Column(JSON))
    authentication_results: dict = Field(default_factory=dict, sa_column=Column(JSON))
    mime_structure: list = Field(default_factory=list, sa_column=Column(JSON))
    body_text: str = ""
    body_html: str = ""
    attachments: list = Field(default_factory=list, sa_column=Column(JSON))

    created_at: datetime = Field(default_factory=_utcnow)

    case: Optional[Case] = Relationship(back_populates="email_analyses")
    header_auth_result: Optional["HeaderAuthResult"] = Relationship(
        back_populates="email_analysis",
        sa_relationship_kwargs={"uselist": False},
    )
    detection_result: Optional["DetectionResult"] = Relationship(
        back_populates="email_analysis",
        sa_relationship_kwargs={"uselist": False},
    )


class HeaderAuthResult(SQLModel, table=True):
    """Official PS component 2: header/protocol analysis."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", unique=True)

    spf_result: str = "none"
    spf_domain: str = ""
    dkim_result: str = "none"
    dkim_domain: str = ""
    dmarc_result: str = "none"
    dmarc_policy: str = ""
    spf_aligned: bool = False
    dkim_aligned: bool = False

    routing_anomaly_flags: list = Field(default_factory=list, sa_column=Column(JSON))
    received_chain: list = Field(default_factory=list, sa_column=Column(JSON))
    auth_cross_check: dict = Field(default_factory=dict, sa_column=Column(JSON))

    email_analysis: Optional[EmailAnalysis] = Relationship(back_populates="header_auth_result")


class DetectionResult(SQLModel, table=True):
    """Official PS component 1: fraudulent email detection engine. Per-signal
    evidence now lives in the Signal table (models/signal.py), not inline here."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", unique=True)

    classification_label: str = ClassificationLabel.legitimate.value
    fraud_score: int = 0
    threat_category: str = ThreatCategory.legitimate.value
    secondary_indicators: list = Field(default_factory=list, sa_column=Column(JSON))

    email_analysis: Optional[EmailAnalysis] = Relationship(back_populates="detection_result")
