import ssl
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import dns.resolver
import whois
import requests

from techstack import fetch_tech_stack
from takeover import check_takeovers
from breach import fetch_breaches
from ports import scan_ports


# ── SSRF guard ────────────────────────────────────────────────────────────────

def _is_public_host(hostname: str) -> bool:
    """
    Resolve hostname to an IP and reject anything that isn't a routable public
    address. Blocks RFC1918, loopback, link-local, and reserved ranges to
    prevent Server-Side Request Forgery (SSRF).
    """
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except Exception:
        return False


# ── Individual fetchers ───────────────────────────────────────────────────────

def fetch_ssl(domain: str) -> dict:
    if not _is_public_host(domain):
        return {"error": "Domain resolves to a non-public address"}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return {"error": str(e)}

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))

    not_after = cert.get("notAfter", "")
    try:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_remaining = (expiry_dt - datetime.now(timezone.utc)).days
    except Exception:
        days_remaining = None

    sans = [val for typ, val in cert.get("subjectAltName", []) if typ == "DNS"]

    return {
        "subject_cn":        subject.get("commonName"),
        "issuer_cn":         issuer.get("commonName"),
        "issuer_org":        issuer.get("organizationName"),
        "valid_from":        cert.get("notBefore"),
        "valid_until":       not_after,
        "days_remaining":    str(days_remaining) if days_remaining is not None else None,
        "expired":           str(days_remaining < 0) if days_remaining is not None else None,
        "serial_number":     cert.get("serialNumber"),
        "subject_alt_names": sans,
    }


def fetch_dns(domain: str) -> dict:
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    # DMARC lives at _dmarc.<domain>, not the root domain
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        records["DMARC"] = [str(r) for r in answers]
    except Exception:
        records["DMARC"] = []

    return records


def fetch_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        def _str(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val is not None else None

        return {
            "registrar":       _str(w.registrar),
            "creation_date":   _str(w.creation_date),
            "expiration_date": _str(w.expiration_date),
            "name_servers":    _str(w.name_servers),
            "status":          _str(w.status),
            "emails":          _str(w.emails),
            "org":             _str(w.org),
            "country":         _str(w.country),
        }
    except Exception as e:
        return {"error": str(e)}


def fetch_headers(domain: str) -> dict:
    if not _is_public_host(domain):
        return {"error": "Domain resolves to a non-public address"}

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (OSINT-Aggregator/1.0)"},
            )
            return dict(resp.headers)
        except Exception:
            continue
    return {"error": "Could not reach host"}


_DNSBLS = ["zen.spamhaus.org", "bl.spamcop.net"]

# Spamhaus returns these IPs when it rate-limits or blocks the querying host.
# They look like a valid "listed" response but are actually error codes.
_DNSBL_ERROR_IPS = {"127.255.255.254", "127.255.255.255"}


def _fetch_geo(ip: str) -> dict:
    """Query ip-api.com (free tier, no key) for geolocation and network info."""
    try:
        fields = "status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile"
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields={fields}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0 (OSINT-Aggregator/1.0)"},
        )
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return {
            "country":     data.get("country"),
            "country_code": data.get("countryCode"),
            "region":      data.get("regionName"),
            "city":        data.get("city"),
            "isp":         data.get("isp"),
            "org":         data.get("org"),
            "asn":         data.get("as"),
            "is_proxy":    data.get("proxy", False),
            "is_hosting":  data.get("hosting", False),
            "is_mobile":   data.get("mobile", False),
        }
    except Exception:
        return {}


def _check_dnsbl(ip: str) -> dict:
    """
    Check an IP against DNS-based blacklists (DNSBLs) using reverse-IP
    lookups. Returns a dict of {blacklist: 'listed' | 'clean' | 'error'}.
    """
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
    except Exception:
        return {}

    results = {}
    for bl in _DNSBLS:
        try:
            answers = dns.resolver.resolve(f"{reversed_ip}.{bl}", "A")
            # Only count as listed if the returned IP is a genuine listing,
            # not a Spamhaus error code (rate-limited / querying host blocked).
            genuine = [str(r) for r in answers if str(r) not in _DNSBL_ERROR_IPS]
            results[bl] = "listed" if genuine else "error"
        except dns.resolver.NXDOMAIN:
            results[bl] = "clean"
        except Exception:
            results[bl] = "error"
    return results


def fetch_ip_reputation(domain: str) -> list:
    """
    Resolve the domain's A records, then for each IP fetch geolocation
    data and DNSBL reputation. Returns a list of per-IP result dicts.
    Uses public resolvers (8.8.8.8 / 1.1.1.1) so CDN-heavy domains
    return globally representative IPs, not the scan server's nearest edge.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        answers = resolver.resolve(domain, "A")
        ips = [str(r) for r in answers][:3]   # cap at 3 IPs
    except Exception:
        return []

    results = []
    for ip in ips:
        geo = _fetch_geo(ip)
        blacklists = _check_dnsbl(ip)
        entry: dict = {"ip": ip, **geo, "blacklists": blacklists}
        results.append(entry)
    return results


def fetch_ct_subdomains(domain: str) -> dict:
    """
    Query the crt.sh Certificate Transparency log aggregator for all certs
    ever issued for *.domain. Returns unique discovered subdomains.
    """
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0 (OSINT-Aggregator/1.0)"},
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        return {"error": str(e)}

    subdomains: set = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.").lower()
            # Filter out email addresses that leak into CT logs via SAN fields
            if "@" in name:
                continue
            if name.endswith(f".{domain}") and name != domain:
                subdomains.add(name)

    return {
        "subdomains": sorted(subdomains),
        "total":      len(subdomains),
    }


# ── Aggregator ────────────────────────────────────────────────────────────────

def run_all(domain: str) -> dict:
    errors: dict = {}

    # Run all independent fetches in parallel
    tasks = {
        "dns":           lambda: fetch_dns(domain),
        "whois":         lambda: fetch_whois(domain),
        "ssl":           lambda: fetch_ssl(domain),
        "headers":       lambda: fetch_headers(domain),
        "ct":            lambda: fetch_ct_subdomains(domain),
        "ip_reputation": lambda: fetch_ip_reputation(domain),
        "tech_stack":    lambda: fetch_tech_stack(domain),
        "breaches":      lambda: fetch_breaches(domain),
        "ports":         lambda: scan_ports(domain),
    }

    results = {}
    with ThreadPoolExecutor(max_workers=9) as executor:
        futures = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                results[key] = {"error": str(e)}

    dns_data     = results["dns"]
    whois_data   = results["whois"]
    ssl_data     = results["ssl"]
    headers_data = results["headers"]
    ct_data      = results["ct"]
    ip_rep_data  = results["ip_reputation"]
    tech_data    = results["tech_stack"]
    breach_data  = results["breaches"]
    ports_data   = results["ports"]

    # Takeover check depends on CT results — runs after
    subdomains    = ct_data.get("subdomains", []) if isinstance(ct_data, dict) else []
    takeover_data = check_takeovers(subdomains)

    if "error" in whois_data:
        errors["whois"] = whois_data.pop("error")
    if "error" in ssl_data:
        errors["ssl"] = ssl_data.pop("error")
    if "error" in headers_data:
        errors["headers"] = headers_data.pop("error")
    if isinstance(ct_data, dict) and "error" in ct_data:
        errors["ct"] = ct_data.pop("error")
    if isinstance(tech_data, dict) and "error" in tech_data:
        errors["tech_stack"] = tech_data.pop("error")

    return {
        "domain":        domain,
        "dns":           dns_data,
        "whois":         whois_data,
        "ssl":           ssl_data,
        "ip_reputation": ip_rep_data,
        "tech_stack":    tech_data,
        "headers":       headers_data,
        "ct":            ct_data,
        "takeover":      takeover_data,
        "breaches":      breach_data,
        "ports":         ports_data,
        "errors":        errors,
    }
