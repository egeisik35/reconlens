"""
Subdomain takeover detection.

For each subdomain from CT logs:
  1. Resolve CNAME chain — flag NXDOMAIN as dangling (MEDIUM)
  2. Match CNAME against known vulnerable service fingerprints
  3. HTTP probe the subdomain and check for unclaimed-service signatures
  4. Flag confirmed matches as vulnerable (HIGH)
"""
import logging
import socket
import ipaddress

import dns.resolver
import dns.exception
import requests

logger = logging.getLogger(__name__)

# ── Fingerprints ───────────────────────────────────────────────────────────────
# Each entry: (cname_pattern, service_name, http_signature)
# cname_pattern: substring matched against the final CNAME target (lowercase)
# http_signature: substring to look for in the HTTP response body

_FINGERPRINTS = [
    ("github.io",              "GitHub Pages",  "There isn't a GitHub Pages site here"),
    ("s3.amazonaws.com",       "AWS S3",        "NoSuchBucket"),
    ("s3-website",             "AWS S3",        "The specified bucket does not exist"),
    ("herokuapp.com",          "Heroku",        "No such app"),
    ("netlify.app",            "Netlify",       "Not Found - Request ID"),
    ("myshopify.com",          "Shopify",       "Sorry, this shop is currently unavailable"),
    ("ghost.io",               "Ghost",         "The thing you were looking for is no longer here"),
    ("surge.sh",               "Surge.sh",      "project not found"),
    ("azurewebsites.net",      "Azure",         "404 Web Site not found"),
    ("readme.io",              "Readme.io",     "Project doesnt exist"),
    ("zendesk.com",            "Zendesk",       "Help Center Closed"),
    ("tumblr.com",             "Tumblr",        "Whatever you were looking for doesn't live here"),
    ("pantheonsite.io",        "Pantheon",      "The gods are wise, but do not know of the site"),
    ("wpengine.com",           "WPEngine",      "The site you were looking for couldn't be found"),
    ("fastly.net",             "Fastly",        "Fastly error: unknown domain"),
    ("unbounce.com",           "Unbounce",      "The requested URL / was not found on this server"),
    ("cargo.site",             "Cargo",         "If you're moving your domain away from Cargo"),
]

_PROBE_TIMEOUT = 5      # seconds per HTTP probe
_MAX_PROBES    = 20     # max subdomains to actively probe


# ── SSRF guard (mirrors osint.py) ─────────────────────────────────────────────

def _is_public_host(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return not (
            ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_reserved or ip.is_multicast or ip.is_unspecified
        )
    except Exception:
        return False


# ── DNS helpers ───────────────────────────────────────────────────────────────

def _resolve_cname_chain(subdomain: str) -> tuple[str | None, bool]:
    """
    Returns (final_cname_target, nxdomain).
    final_cname_target is None if no CNAME exists or resolution fails.
    nxdomain is True if the domain does not exist at all.
    """
    try:
        answer = dns.resolver.resolve(subdomain, "CNAME")
        cname = str(answer[0].target).rstrip(".").lower()
        return cname, False
    except dns.resolver.NXDOMAIN:
        return None, True
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.DNSException):
        return None, False


# ── HTTP probe ────────────────────────────────────────────────────────────────

def _probe(subdomain: str, signature: str) -> bool:
    """Returns True if the HTTP response body contains the unclaimed signature."""
    if not _is_public_host(subdomain):
        return False
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=_PROBE_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconLens/1.0)"},
            )
            if signature.lower() in r.text.lower():
                return True
        except Exception:
            pass
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def check_takeovers(subdomains: list[str]) -> list[dict]:
    """
    Check a list of subdomains for takeover vulnerabilities.
    Returns a list of findings dicts.
    """
    findings = []
    probed   = 0

    # Skip obviously internal subdomains — not public-facing, not real takeover risks
    _INTERNAL = ("corp.", "int.", "intranet.", "internal.", "stg.", "dev.", "staging.", "test.", "qa.", "grid.")

    for sub in subdomains:
        if probed >= _MAX_PROBES:
            break

        # Skip internal subdomains
        if any(f".{pat}" in sub or sub.startswith(pat) for pat in _INTERNAL):
            continue

        try:
            cname, nxdomain = _resolve_cname_chain(sub)

            if nxdomain:
                findings.append({
                    "subdomain": sub,
                    "cname":     None,
                    "service":   None,
                    "status":    "dangling",
                    "severity":  "medium",
                    "detail":    "No DNS record exists — dangling DNS entry.",
                })
                probed += 1
                continue

            if not cname:
                probed += 1
                continue

            # Match against fingerprints
            matched_service   = None
            matched_signature = None
            for pattern, service, signature in _FINGERPRINTS:
                if pattern in cname:
                    matched_service   = service
                    matched_signature = signature
                    break

            if not matched_service:
                probed += 1
                continue

            # HTTP probe to confirm
            probed += 1
            confirmed = _probe(sub, matched_signature)

            if confirmed:
                findings.append({
                    "subdomain": sub,
                    "cname":     cname,
                    "service":   matched_service,
                    "status":    "vulnerable",
                    "severity":  "high",
                    "detail":    f"CNAME points to unclaimed {matched_service} resource.",
                })
            else:
                # CNAME matches a risky service but probe didn't confirm
                findings.append({
                    "subdomain": sub,
                    "cname":     cname,
                    "service":   matched_service,
                    "status":    "check_failed",
                    "severity":  "info",
                    "detail":    f"CNAME points to {matched_service} — could not confirm if unclaimed.",
                })

        except Exception as e:
            logger.debug("Takeover check failed for %s: %s", sub, e)
            probed += 1

    return findings
