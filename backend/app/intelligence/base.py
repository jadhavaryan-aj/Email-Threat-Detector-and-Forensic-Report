"""PS components 10/11/12: pluggable intelligence-provider interfaces. Each has one
local, no-API-key-required default implementation in this package (real DNS/WHOIS for
domains, ip-api.com + Spamhaus for IPs, an honest "unavailable" for third-party threat
intel). A paid provider (VirusTotal, AbuseIPDB, IPinfo, ...) can be dropped in later by
implementing the same Protocol — nothing else in the pipeline needs to change."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class DomainIntelResult:
    domain: str
    registered_domain: str = ""
    tld: str = ""
    mx_records: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    registrar: str | None = None
    created_date: str | None = None
    age_days: int | None = None
    dnsbl_listed: bool = False
    source: str = "local_dns"
    available: bool = True
    unavailable_reason: str | None = None


@dataclass
class IpIntelResult:
    ip: str
    ip_version: int = 4
    is_public: bool = True
    asn: str | None = None
    asn_org: str | None = None
    country: str | None = None
    region: str | None = None
    city: str | None = None
    isp_org: str | None = None
    is_vpn_or_proxy_or_tor: bool | None = None
    dnsbl_listed: bool = False
    source: str = "ip-api"
    available: bool = True
    unavailable_reason: str | None = None
    disclaimer: str = (
        "Represents observed network infrastructure at the time of analysis, not the "
        "physical location or identity of the sender."
    )


@dataclass
class ThreatIntelResult:
    provider: str
    indicator_type: str
    indicator_value: str
    available: bool = False
    verdict: str | None = None
    raw_response: dict = field(default_factory=dict)


class DomainIntelligenceProvider(Protocol):
    def lookup(self, domain: str) -> DomainIntelResult: ...


class IPIntelligenceProvider(Protocol):
    def lookup(self, ip: str) -> IpIntelResult: ...


class ThreatIntelligenceProvider(Protocol):
    def check_ip(self, ip: str) -> ThreatIntelResult: ...
    def check_domain(self, domain: str) -> ThreatIntelResult: ...
