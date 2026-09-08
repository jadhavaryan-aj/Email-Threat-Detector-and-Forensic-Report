"""Default IPIntelligenceProvider: ip-api.com (free, no key, ~45 req/min) for
ASN/org/geo, plus a real Spamhaus ZEN DNSBL check for reputation. Every field here
describes *observed infrastructure* — never attacker attribution or physical location
of a person; see IpIntelResult.disclaimer, which is persisted and always shown."""

import socket

import requests

from app.intelligence.base import IpIntelResult
from app.utils.ip_utils import is_public_ip

_HTTP_TIMEOUT = 3.0
_SOCKET_TIMEOUT = 3.0


def _zen_listed(ip: str) -> bool:
    """Spamhaus ZEN combined IP blocklist — free, no key, reversed-octet A lookup."""
    octets = ip.split(".")
    if len(octets) != 4:
        return False  # IPv6 not supported by this lookup form; treat as "not listed"
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_SOCKET_TIMEOUT)
        reversed_ip = ".".join(reversed(octets))
        socket.gethostbyname(f"{reversed_ip}.zen.spamhaus.org")
        return True
    except OSError:
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)


class LocalIpIntelligenceProvider:
    name = "ip-api"

    def lookup(self, ip: str) -> IpIntelResult:
        if not ip:
            return IpIntelResult(ip=ip, available=False, unavailable_reason="empty ip")

        result = IpIntelResult(ip=ip, is_public=is_public_ip(ip), source=self.name)
        if not result.is_public:
            result.available = False
            result.unavailable_reason = "private/reserved address — no public intelligence applies"
            return result

        try:
            result.dnsbl_listed = _zen_listed(ip)
        except Exception:
            pass  # reputation check is best-effort; absence shouldn't block geo/ASN data

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,regionName,city,isp,org,as,proxy,hosting"},
                timeout=_HTTP_TIMEOUT,
            )
            data = response.json()
            if data.get("status") != "success":
                result.available = False
                result.unavailable_reason = data.get("message", "lookup failed")
                return result

            result.country = data.get("country")
            result.region = data.get("regionName")
            result.city = data.get("city")
            result.isp_org = data.get("isp") or data.get("org")
            asn_field = data.get("as") or ""
            asn_parts = asn_field.split(" ", 1)
            result.asn = asn_parts[0] if asn_parts and asn_parts[0] else None
            result.asn_org = asn_parts[1] if len(asn_parts) > 1 else None
            result.is_vpn_or_proxy_or_tor = bool(data.get("proxy"))
        except Exception as exc:
            result.available = False
            result.unavailable_reason = f"ip-api lookup failed: {exc}"

        return result
