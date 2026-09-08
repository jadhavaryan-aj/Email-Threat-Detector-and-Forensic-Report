import ipaddress


def is_public_ip(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def first_public_ip(ips: list[str | None]) -> str | None:
    for ip in ips:
        if is_public_ip(ip):
            return ip
    return None
