import dns.resolver
import whois
import requests


def fetch_dns(domain: str) -> dict:
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


def fetch_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        def _str(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val is not None else None

        return {
            "registrar": _str(w.registrar),
            "creation_date": _str(w.creation_date),
            "expiration_date": _str(w.expiration_date),
            "name_servers": _str(w.name_servers),
            "status": _str(w.status),
            "emails": _str(w.emails),
            "org": _str(w.org),
            "country": _str(w.country),
        }
    except Exception as e:
        return {"error": str(e)}


def fetch_headers(domain: str) -> dict:
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


def run_all(domain: str) -> dict:
    errors: dict = {}

    dns_data = fetch_dns(domain)
    whois_data = fetch_whois(domain)
    headers_data = fetch_headers(domain)

    if "error" in whois_data:
        errors["whois"] = whois_data.pop("error")
    if "error" in headers_data:
        errors["headers"] = headers_data.pop("error")

    return {
        "domain": domain,
        "dns": dns_data,
        "whois": whois_data,
        "headers": headers_data,
        "errors": errors,
    }
