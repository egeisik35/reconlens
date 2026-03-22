"""
Email sending via the Resend API.
Handles both confirmation emails (on watch setup) and change alerts.
"""
import logging
import os

import resend

logger = logging.getLogger(__name__)

_CATEGORY_LABELS = {
    "cdn": "CDN", "web_server": "Web Server", "cms": "CMS / Platform",
    "language": "Language / Runtime", "js_framework": "JS Framework",
    "analytics": "Analytics", "waf": "WAF / Security", "hosting": "Hosting",
}

_BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
_FROM     = os.environ.get("FROM_EMAIL", "onboarding@resend.dev")


def _api_key() -> str:
    key = os.environ.get("RESEND_API_KEY", "")
    if not key or key.startswith("re_your_"):
        raise RuntimeError("RESEND_API_KEY is not configured in .env")
    return key


# ── HTML helpers ──────────────────────────────────────────────────────────────

def _change_rows(changes: list) -> str:
    rows = ""
    for c in changes:
        t = c["type"]

        if t == "dns_changed":
            rtype = c["record_type"]
            detail = ""
            if c.get("added"):
                detail += f'<span style="color:#16a34a">+ {", ".join(c["added"])}</span><br>'
            if c.get("removed"):
                detail += f'<span style="color:#dc2626">- {", ".join(c["removed"])}</span>'
            rows += _row(f"DNS {rtype} Record Change", detail)

        elif t == "ssl_expiry":
            days = c["days_remaining"]
            color = "#dc2626" if days <= 14 else "#d97706"
            rows += _row(
                "SSL Certificate Expiry",
                f'<span style="color:{color};font-weight:700">'
                f'{"EXPIRED" if days < 0 else f"Expires in {days} days"}</span>',
            )

        elif t == "ssl_changed":
            field = c["field"].replace("_", " ").title()
            rows += _row(
                f"SSL {field} Changed",
                f'<span style="color:#6b7280">{c["old"]}</span> &rarr; '
                f'<span style="color:#111827">{c["new"]}</span>',
            )

        elif t == "new_subdomains":
            subs = ", ".join(c["added"][:20])
            extra = f" (+{len(c['added'])-20} more)" if len(c["added"]) > 20 else ""
            rows += _row(
                f"{len(c['added'])} New Subdomain(s) in CT Logs",
                f'<span style="color:#16a34a">{subs}{extra}</span>',
            )

        elif t == "tech_changed":
            cat = _CATEGORY_LABELS.get(c["category"], c["category"])
            detail = ""
            if c.get("added"):
                detail += f'<span style="color:#16a34a">+ {", ".join(c["added"])}</span><br>'
            if c.get("removed"):
                detail += f'<span style="color:#dc2626">- {", ".join(c["removed"])}</span>'
            rows += _row(f"Tech Stack Change ({cat})", detail)

    return rows


def _row(label: str, detail: str) -> str:
    return f"""
    <tr>
      <td style="padding:10px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top;
                 white-space:nowrap;color:#6b7280;font-size:12px;width:200px">{label}</td>
      <td style="padding:10px 12px;border-bottom:1px solid #f3f4f6;font-size:12px;
                 word-break:break-all">{detail}</td>
    </tr>"""


def _base_html(title: str, body: str, monitor_id: str) -> str:
    unwatch_url = f"{_BASE_URL}/api/unwatch?id={monitor_id}"
    return f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f9fafb;font-family:'Courier New',monospace">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:32px 16px">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">

        <!-- Header -->
        <tr>
          <td style="background:#0d1117;padding:20px 28px">
            <span style="color:#58a6ff;font-size:18px;font-weight:700">OSINT Aggregator</span>
            <span style="color:#8b949e;font-size:11px;margin-left:12px">Domain Monitor</span>
          </td>
        </tr>

        <!-- Title -->
        <tr>
          <td style="padding:24px 28px 8px">
            <h1 style="margin:0;font-size:18px;color:#111827">{title}</h1>
          </td>
        </tr>

        <!-- Body -->
        {body}

        <!-- Footer -->
        <tr>
          <td style="padding:20px 28px;border-top:1px solid #f3f4f6">
            <p style="margin:0;font-size:11px;color:#9ca3af">
              You're receiving this because you subscribed to domain monitoring.<br>
              <a href="{unwatch_url}" style="color:#6b7280">Unsubscribe from these alerts</a>
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


# ── Public API ────────────────────────────────────────────────────────────────

def send_confirmation(domain: str, email: str, monitor_id: str) -> None:
    resend.api_key = _api_key()

    body = f"""
    <tr><td style="padding:8px 28px 20px;color:#6b7280;font-size:13px">
      We're now watching <strong style="color:#111827">{domain}</strong>.
      You'll receive an alert when any of the following change:
    </td></tr>
    <tr><td style="padding:0 28px 24px">
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#f9fafb;border-radius:6px;font-size:12px">
        <tr><td style="padding:10px 14px;color:#374151">&#9654; DNS records (A, MX, NS, TXT)</td></tr>
        <tr><td style="padding:10px 14px;color:#374151;border-top:1px solid #e5e7eb">
              &#9654; SSL certificate change or expiry &le; 30 days</td></tr>
        <tr><td style="padding:10px 14px;color:#374151;border-top:1px solid #e5e7eb">
              &#9654; New subdomains in Certificate Transparency logs</td></tr>
        <tr><td style="padding:10px 14px;color:#374151;border-top:1px solid #e5e7eb">
              &#9654; Tech stack fingerprint changes (CDN, CMS, frameworks)</td></tr>
      </table>
    </td></tr>"""

    html = _base_html(f"Now watching {domain}", body, monitor_id)

    resend.Emails.send({
        "from":    _FROM,
        "to":      [email],
        "subject": f"Watching {domain} — OSINT Aggregator",
        "html":    html,
    })
    logger.info("Confirmation sent to %s for %s", email, domain)


def send_alert(domain: str, email: str, monitor_id: str, changes: list) -> None:
    resend.api_key = _api_key()

    change_count = len(changes)
    rows_html = _change_rows(changes)

    body = f"""
    <tr><td style="padding:8px 28px 16px;color:#6b7280;font-size:13px">
      <strong style="color:#dc2626">{change_count} change{"s" if change_count != 1 else ""}</strong>
      detected for <strong style="color:#111827">{domain}</strong>.
    </td></tr>
    <tr><td style="padding:0 28px 24px">
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border:1px solid #e5e7eb;border-radius:6px;overflow:hidden">
        {rows_html}
      </table>
    </td></tr>"""

    html = _base_html(f"Alert: {domain} has changed", body, monitor_id)

    resend.Emails.send({
        "from":    _FROM,
        "to":      [email],
        "subject": f"Alert: Changes detected for {domain}",
        "html":    html,
    })
    logger.info("Alert sent to %s for %s (%d changes)", email, domain, change_count)
