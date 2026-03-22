"""
Snapshot engine and diff logic for domain monitoring.

A snapshot captures only the fields we want to alert on — keeping it lean
avoids false positives from ephemeral header values (dates, cache tokens, etc.).
"""
import logging
from datetime import datetime, timezone

from osint import fetch_dns, fetch_ssl, fetch_ct_subdomains
from techstack import fetch_tech_stack

logger = logging.getLogger(__name__)


# ── Snapshot ──────────────────────────────────────────────────────────────────

def take_snapshot(domain: str) -> dict:
    """
    Run the four checks we monitor and return a normalised snapshot dict.
    All list values are sorted for stable comparison.
    """
    dns_raw  = fetch_dns(domain)
    ssl_raw  = fetch_ssl(domain)
    ct_raw   = fetch_ct_subdomains(domain)
    tech_raw = fetch_tech_stack(domain)

    days_str = ssl_raw.get("days_remaining") if isinstance(ssl_raw, dict) else None

    return {
        "dns": {
            rtype: sorted(records)
            for rtype, records in dns_raw.items()
            if records
        },
        "ssl": {
            "subject_cn":    ssl_raw.get("subject_cn") if isinstance(ssl_raw, dict) else None,
            "issuer_cn":     ssl_raw.get("issuer_cn")  if isinstance(ssl_raw, dict) else None,
            "valid_until":   ssl_raw.get("valid_until") if isinstance(ssl_raw, dict) else None,
            "days_remaining": days_str,
        },
        "ct": {
            "subdomains": sorted(ct_raw.get("subdomains", [])) if isinstance(ct_raw, dict) else [],
        },
        "tech_stack": {
            cat: sorted(techs)
            for cat, techs in (tech_raw.items() if isinstance(tech_raw, dict) else {}.items())
            if isinstance(techs, list) and techs
        },
    }


# ── Diff ──────────────────────────────────────────────────────────────────────

def diff_snapshots(old: dict, new: dict) -> list:
    """
    Compare two snapshots and return a list of change descriptors.
    Returns [] when nothing meaningful changed.
    """
    changes: list = []

    # ── DNS ──────────────────────────────────────────────────────────────────
    old_dns = old.get("dns", {})
    new_dns = new.get("dns", {})
    for rtype in sorted(set(list(old_dns) + list(new_dns))):
        added   = sorted(set(new_dns.get(rtype, [])) - set(old_dns.get(rtype, [])))
        removed = sorted(set(old_dns.get(rtype, [])) - set(new_dns.get(rtype, [])))
        if added or removed:
            changes.append({
                "type":        "dns_changed",
                "record_type": rtype,
                "added":       added,
                "removed":     removed,
            })

    # ── SSL certificate ───────────────────────────────────────────────────────
    new_ssl = new.get("ssl", {})
    old_ssl = old.get("ssl", {})

    # Cert was replaced (subject or expiry date changed)
    for field in ("subject_cn", "issuer_cn", "valid_until"):
        ov, nv = old_ssl.get(field), new_ssl.get(field)
        if ov and nv and ov != nv:
            changes.append({"type": "ssl_changed", "field": field, "old": ov, "new": nv})

    # Expiry warning (fire every check when ≤ 30 days)
    try:
        days = int(new_ssl.get("days_remaining") or 9999)
        if days <= 30:
            changes.append({"type": "ssl_expiry", "days_remaining": days})
    except (ValueError, TypeError):
        pass

    # ── Certificate Transparency — new subdomains ─────────────────────────────
    old_subs = set(old.get("ct", {}).get("subdomains", []))
    new_subs = set(new.get("ct", {}).get("subdomains", []))
    added_subs = sorted(new_subs - old_subs)
    if added_subs:
        changes.append({"type": "new_subdomains", "added": added_subs})

    # ── Tech stack ────────────────────────────────────────────────────────────
    old_tech = old.get("tech_stack", {})
    new_tech = new.get("tech_stack", {})
    for cat in sorted(set(list(old_tech) + list(new_tech))):
        added_t   = sorted(set(new_tech.get(cat, [])) - set(old_tech.get(cat, [])))
        removed_t = sorted(set(old_tech.get(cat, [])) - set(new_tech.get(cat, [])))
        if added_t or removed_t:
            changes.append({
                "type":     "tech_changed",
                "category": cat,
                "added":    added_t,
                "removed":  removed_t,
            })

    return changes
