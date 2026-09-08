"""Default ThreatIntelligenceProvider: real calls to AbuseIPDB/VirusTotal *if* the
user has configured an API key in .env; otherwise returns a structured
available=False result. Never fabricates a verdict, and a missing/invalid key or a
network failure must never block the rest of the pipeline — see PS sections 12/25/30."""

import requests

from app.config import settings
from app.intelligence.base import ThreatIntelResult

_HTTP_TIMEOUT = 3.0


class EnvThreatIntelligenceProvider:
    def check_ip(self, ip: str) -> ThreatIntelResult:
        if not settings.abuseipdb_api_key:
            return ThreatIntelResult(
                provider="abuseipdb", indicator_type="ip", indicator_value=ip, available=False
            )
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                timeout=_HTTP_TIMEOUT,
            )
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            verdict = "malicious" if score >= 50 else "suspicious" if score >= 10 else "clean"
            return ThreatIntelResult(
                provider="abuseipdb",
                indicator_type="ip",
                indicator_value=ip,
                available=True,
                verdict=verdict,
                raw_response=data,
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider="abuseipdb",
                indicator_type="ip",
                indicator_value=ip,
                available=False,
                raw_response={"error": str(exc)},
            )

    def check_domain(self, domain: str) -> ThreatIntelResult:
        if not settings.virustotal_api_key:
            return ThreatIntelResult(
                provider="virustotal", indicator_type="domain", indicator_value=domain, available=False
            )
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.virustotal_api_key},
                timeout=_HTTP_TIMEOUT,
            )
            attributes = response.json().get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            verdict = "malicious" if malicious_count > 0 else "clean"
            return ThreatIntelResult(
                provider="virustotal",
                indicator_type="domain",
                indicator_value=domain,
                available=True,
                verdict=verdict,
                raw_response=stats,
            )
        except Exception as exc:
            return ThreatIntelResult(
                provider="virustotal",
                indicator_type="domain",
                indicator_value=domain,
                available=False,
                raw_response={"error": str(exc)},
            )
