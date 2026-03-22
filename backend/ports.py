"""
Open port scanner.
Checks well-known TCP ports on the target domain's primary IP.
All probes run in parallel with a short per-port timeout.
"""
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

_TIMEOUT = 1.5   # seconds per port probe

# (port, service_name, risk_level)
_PORTS = [
    (21,    "FTP",         "high"),
    (22,    "SSH",         "medium"),
    (23,    "Telnet",      "critical"),
    (25,    "SMTP",        "medium"),
    (53,    "DNS",         "medium"),
    (80,    "HTTP",        "info"),
    (443,   "HTTPS",       "info"),
    (445,   "SMB",         "critical"),
    (3306,  "MySQL",       "high"),
    (3389,  "RDP",         "critical"),
    (5432,  "PostgreSQL",  "high"),
    (6379,  "Redis",       "high"),
    (8080,  "HTTP-Alt",    "info"),
    (8443,  "HTTPS-Alt",   "info"),
    (27017, "MongoDB",     "high"),
]


def _is_public_host(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_reserved or ip.is_multicast or ip.is_unspecified
        )
    except Exception:
        return False


def _check_port(ip: str, port: int, service: str, risk: str) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=_TIMEOUT):
            return {"port": port, "service": service, "risk": risk, "status": "open"}
    except Exception:
        return None


def scan_ports(domain: str) -> list[dict]:
    """
    Scan common ports on the domain's primary IP.
    Returns list of open port dicts (port, service, risk, status).
    """
    if not _is_public_host(domain):
        return []

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return []

    open_ports = []
    with ThreadPoolExecutor(max_workers=len(_PORTS)) as executor:
        futures = {
            executor.submit(_check_port, ip, port, service, risk): port
            for port, service, risk in _PORTS
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])
    return open_ports
