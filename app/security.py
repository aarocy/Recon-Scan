import ipaddress
import socket
from urllib.parse import urlparse


def normalize_and_validate_target(target: str) -> str:
    cleaned = (target or "").strip().lower()
    if not cleaned:
        raise ValueError("Target is required")

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        cleaned = (parsed.hostname or "").strip().lower()

    cleaned = cleaned.strip(".")
    if not cleaned:
        raise ValueError("Target is invalid")

    if _is_blocked_ip_or_local_name(cleaned):
        raise ValueError("Private, loopback, local, or reserved targets are not allowed")

    return cleaned


def _is_blocked_ip_or_local_name(hostname: str) -> bool:
    if hostname in {"localhost", "localhost.localdomain"}:
        return True
    if hostname.endswith(".local"):
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return _is_non_public_ip(ip)
    except ValueError:
        pass

    try:
        _, _, addresses = socket.gethostbyname_ex(hostname)
    except Exception:
        return False

    for addr in addresses:
        try:
            if _is_non_public_ip(ipaddress.ip_address(addr)):
                return True
        except ValueError:
            continue
    return False


def _is_non_public_ip(ip) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
