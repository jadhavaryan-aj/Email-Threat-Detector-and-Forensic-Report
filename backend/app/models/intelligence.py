from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ExtractedUrl(SQLModel, table=True):
    """PS component 1/9: per-URL lexical risk analysis."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    raw_url: str
    anchor_text: Optional[str] = None
    normalized_url: str = ""
    hostname: str = ""
    registered_domain: str = ""
    scheme: str = ""
    is_ip_based: bool = False
    subdomain_count: int = 0
    has_punycode: bool = False
    is_shortener: bool = False
    display_text_mismatch: bool = False
    lookalike_of_brand: Optional[str] = None
    lexical_risk_score: int = 0


class DomainIntelligence(SQLModel, table=True):
    """PS component 3: domain intelligence (DNS/WHOIS). `available=False` with
    `unavailable_reason` set means the lookup failed/timed out — never a crash."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    domain: str
    registered_domain: str = ""
    tld: str = ""
    mx_records: list = Field(default_factory=list, sa_column=Column(JSON))
    nameservers: list = Field(default_factory=list, sa_column=Column(JSON))
    registrar: Optional[str] = None
    created_date: Optional[str] = None
    age_days: Optional[int] = None
    dnsbl_listed: bool = False
    source: str = "local_dns"
    available: bool = True
    unavailable_reason: Optional[str] = None


class IpIntelligence(SQLModel, table=True):
    """PS component 3: IP intelligence. `disclaimer` is persisted verbatim (not just
    added at render time) so it always travels with the data, into the PDF report too."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    ip: str
    ip_version: int = 4
    is_public: bool = True
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp_org: Optional[str] = None
    is_vpn_or_proxy_or_tor: Optional[bool] = None
    dnsbl_listed: bool = False
    source: str = "ip-api"
    available: bool = True
    unavailable_reason: Optional[str] = None
    disclaimer: str = (
        "Represents observed network infrastructure at the time of analysis, not the "
        "physical location or identity of the sender."
    )


class ThreatIntelResult(SQLModel, table=True):
    """PS component 3/12: third-party threat-intel lookups. `available=False` is the
    honest default with no API key configured — never fabricated."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email_analysis_id: int = Field(foreign_key="emailanalysis.id", index=True)

    provider: str
    indicator_type: str
    indicator_value: str
    available: bool = False
    verdict: Optional[str] = None
    raw_response: dict = Field(default_factory=dict, sa_column=Column(JSON))
    checked_at: datetime = Field(default_factory=_utcnow)
