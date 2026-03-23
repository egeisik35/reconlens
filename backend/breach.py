"""
Breach intelligence via HaveIBeenPwned public API.
Uses the free domain-level endpoint — no API key required.
"""
import logging
import time

import requests

logger = logging.getLogger(__name__)

_HIBP_URL   = "https://haveibeenpwned.com/api/v3/breaches"
_TIMEOUT    = 8
_USER_AGENT = "ReconLens/1.0 (passive-recon-tool)"


def fetch_breaches(domain: str) -> list[dict]:
    """
    Returns a list of breach dicts for the given domain.
    Each dict has: name, domain, breach_date, pwn_count,
                   data_classes, is_verified, is_sensitive, description
    Returns empty list on any error.
    """
    try:
        time.sleep(0.5)   # respect HIBP rate limit
        resp = requests.get(
            _HIBP_URL,
            params={"domain": domain},
            headers={"User-Agent": _USER_AGENT},
            timeout=_TIMEOUT,
        )

        if resp.status_code == 404:
            return []   # no breaches found — normal

        if resp.status_code == 429:
            logger.warning("HIBP rate limited for %s", domain)
            return []

        resp.raise_for_status()
        raw = resp.json()

    except Exception as e:
        logger.warning("HIBP fetch failed for %s: %s", domain, e)
        return []

    breaches = []
    for b in raw:
        breaches.append({
            "name":         b.get("Name", ""),
            "domain":       b.get("Domain", ""),
            "breach_date":  b.get("BreachDate", ""),
            "pwn_count":    b.get("PwnCount", 0),
            "data_classes": b.get("DataClasses", []),
            "is_verified":  b.get("IsVerified", False),
            "is_sensitive": b.get("IsSensitive", False),
            "description":  "" if b.get("IsSensitive") else b.get("Description", ""),
        })

    # Sort by date descending (most recent first)
    breaches.sort(key=lambda x: x["breach_date"], reverse=True)
    return breaches
