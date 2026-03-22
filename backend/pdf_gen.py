from datetime import datetime, timezone
import weasyprint


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _rows(data: dict, skip_empty: bool = True) -> str:
    html = ""
    for key, val in data.items():
        if skip_empty and (val is None or val == "" or val == [] or val == "None"):
            continue
        if isinstance(val, list):
            cell = " ".join(f'<span class="tag">{_esc(v)}</span>' for v in val)
        else:
            cell = f'<span class="val">{_esc(str(val))}</span>'
        html += f"<tr><td class='key'>{_esc(key)}</td><td>{cell}</td></tr>"
    return html or "<tr><td colspan='2' class='empty'>No data collected</td></tr>"


def _section(title: str, table_html: str, color: str = "#1a56db") -> str:
    return f"""
    <section>
      <div class="section-header" style="border-left:4px solid {color}">
        <h2>{title}</h2>
      </div>
      <table>{table_html}</table>
    </section>
    """


def build_html(data: dict) -> str:
    domain = _esc(data.get("domain", "unknown"))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    dns = data.get("dns", {})
    whois = data.get("whois", {})
    ssl = data.get("ssl", {})
    ip_reputation = data.get("ip_reputation", [])
    tech_stack = data.get("tech_stack", {})
    headers = data.get("headers", {})
    ct = data.get("ct", {})
    takeover = data.get("takeover", [])
    breaches = data.get("breaches", [])
    ports = data.get("ports", [])
    errors = data.get("errors", {})

    # DNS: filter empty record types
    dns_filtered = {k: v for k, v in dns.items() if v}
    dns_html = _rows(dns_filtered, skip_empty=False) if dns_filtered else \
        "<tr><td colspan='2' class='empty'>No DNS records found</td></tr>"

    # SSL expiry banner for PDF
    ssl_banner = ""
    days_str = ssl.get("days_remaining")
    if days_str is not None:
        try:
            days = int(days_str)
            if days < 0:
                ssl_banner = f'<div class="ssl-badge ssl-expired">EXPIRED {abs(days)} days ago</div>'
            elif days < 14:
                ssl_banner = f'<div class="ssl-badge ssl-critical">CRITICAL — expires in {days} days</div>'
            elif days < 30:
                ssl_banner = f'<div class="ssl-badge ssl-warn">Warning — expires in {days} days</div>'
            else:
                ssl_banner = f'<div class="ssl-badge ssl-ok">Valid for {days} more days</div>'
        except ValueError:
            pass

    ssl_skip = {"days_remaining", "expired"}
    ssl_filtered = {k: v for k, v in ssl.items() if k not in ssl_skip and v}
    ssl_html = ssl_banner + ("<table>" + _rows(ssl_filtered) + "</table>" if ssl_filtered else "")

    # Tech stack section
    _TECH_LABELS = {
        "cdn": "CDN", "web_server": "Web Server", "cms": "CMS / Platform",
        "language": "Language / Runtime", "js_framework": "JS Framework",
        "analytics": "Analytics", "waf": "WAF / Security", "hosting": "Hosting",
    }
    _TECH_COLORS = {
        "cdn": "#1d4ed8", "web_server": "#6b7280", "cms": "#7c3aed",
        "language": "#c2410c", "js_framework": "#0e7490", "analytics": "#15803d",
        "waf": "#b91c1c", "hosting": "#4338ca",
    }
    tech_rows_html = ""
    for cat, techs in tech_stack.items():
        if not isinstance(techs, list) or not techs:
            continue
        color = _TECH_COLORS.get(cat, "#6b7280")
        label = _TECH_LABELS.get(cat, cat)
        pills = " ".join(
            f'<span class="tech-pill" style="background:{color}18;border:1px solid {color}55;color:{color}">{_esc(t)}</span>'
            for t in techs
        )
        tech_rows_html += f"""
        <tr>
          <td class="key">{_esc(label)}</td>
          <td>{pills}</td>
        </tr>"""
    tech_html = f"<table>{tech_rows_html}</table>" if tech_rows_html else \
        '<p style="color:#9ca3af;font-style:italic;font-size:8pt">No technologies detected.</p>'

    # IP reputation section
    _ip_skip = {"ip", "is_proxy", "is_hosting", "is_mobile", "blacklists", "country_code"}
    ip_blocks_html = ""
    for host in ip_reputation:
        ip_addr = _esc(host.get("ip", ""))
        cc = _esc(host.get("country_code") or "")

        # Reputation badges
        badges = []
        if host.get("is_proxy"):
            badges.append('<span class="rep-badge rep-danger">Proxy / VPN</span>')
        if host.get("is_hosting"):
            badges.append('<span class="rep-badge rep-warn">Hosting / DC</span>')
        if not host.get("is_proxy") and not host.get("is_hosting"):
            badges.append('<span class="rep-badge rep-ok">Residential / ISP</span>')
        for bl_name, bl_status in (host.get("blacklists") or {}).items():
            cls = "rep-danger" if bl_status == "listed" else "rep-ok" if bl_status == "clean" else "rep-neutral"
            badges.append(f'<span class="rep-badge {cls}">{_esc(bl_name)}: {_esc(bl_status)}</span>')

        geo_rows = "".join(
            f"<tr><td class='key'>{_esc(k)}</td><td><span class='val'>{_esc(str(v))}</span></td></tr>"
            for k, v in host.items()
            if k not in _ip_skip and v not in (None, "", False)
        )
        ip_blocks_html += f"""
        <div class="ip-block">
          <div class="ip-header">
            <span class="ip-addr">{ip_addr}</span>
            {"" if not cc else f'<span class="ip-cc">{cc}</span>'}
            <span class="ip-badges">{"".join(badges)}</span>
          </div>
          <table>{geo_rows}</table>
        </div>"""

    if not ip_blocks_html:
        ip_blocks_html = '<p style="color:#9ca3af;font-style:italic;font-size:8pt">No IP data collected.</p>'

    # CT subdomains section
    ct_subdomains = ct.get("subdomains", [])
    ct_total = ct.get("total", 0)
    if ct_subdomains:
        ct_tags = " ".join(f'<span class="tag">{_esc(s)}</span>' for s in ct_subdomains)
        ct_html = f'<p class="ct-count">{ct_total} subdomain{"s" if ct_total != 1 else ""} discovered via Certificate Transparency logs.</p>{ct_tags}'
    else:
        ct_html = '<p class="ct-count" style="color:#9ca3af;font-style:italic">No subdomains found in CT logs.</p>'

    # Takeover risks section
    _SEV_COLORS = {"high": "#dc2626", "medium": "#d97706", "info": "#6b7280"}
    _SEV_BG     = {"high": "#fee2e2", "medium": "#fef9c3", "info": "#f3f4f6"}
    takeover_html = ""
    actionable = [f for f in takeover if f["status"] != "check_failed"]
    if actionable:
        rows = ""
        for f in actionable:
            sev   = f.get("severity", "info")
            color = _SEV_COLORS.get(sev, "#6b7280")
            bg    = _SEV_BG.get(sev, "#f3f4f6")
            badge = f'<span style="background:{bg};border:1px solid {color};color:{color};border-radius:3pt;font-size:7pt;font-weight:700;padding:1pt 5pt">{_esc(sev.upper())}</span>'
            cname_cell = f'<span style="color:#6b7280;font-size:7.5pt">{_esc(f["cname"])}</span>' if f.get("cname") else '<span style="color:#9ca3af">—</span>'
            rows += f"""<tr>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top">{badge}</td>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top;font-weight:600;color:#111827">{_esc(f["subdomain"])}</td>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top">{cname_cell}</td>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top;color:#6b7280;font-size:7.5pt">{_esc(f["detail"])}</td>
            </tr>"""
        takeover_html = f"""<table>
          <tr style="background:#f9fafb">
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600;width:60pt">Severity</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Subdomain</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">CNAME Target</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Detail</th>
          </tr>{rows}</table>"""
    else:
        takeover_html = '<p style="color:#9ca3af;font-style:italic;font-size:8pt">No takeover vulnerabilities detected.</p>'

    takeover_section = f"""<section>
      <div class="section-header" style="border-left:4px solid #dc2626">
        <h2>Subdomain Takeover Risks</h2>
      </div>
      <div style="padding:6pt 8pt">{takeover_html}</div>
    </section>"""

    # Breach intelligence section
    if breaches:
        total_records = sum(b.get("pwn_count", 0) for b in breaches)
        breach_rows = ""
        for b in breaches:
            count     = f"{b['pwn_count']:,}" if b.get("pwn_count") else "?"
            verified  = "" if b.get("is_verified") else '<span style="background:#f3f4f6;border:1px solid #d1d5db;color:#6b7280;border-radius:3pt;font-size:6.5pt;font-weight:700;padding:1pt 4pt;margin-left:4pt">UNVERIFIED</span>'
            sensitive = '<span style="background:#fef3c7;border:1px solid #fcd34d;color:#92400e;border-radius:3pt;font-size:6.5pt;font-weight:700;padding:1pt 4pt;margin-left:4pt">SENSITIVE</span>' if b.get("is_sensitive") else ""
            pills     = " ".join(f'<span style="background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8;border-radius:3pt;font-size:6.5pt;padding:1pt 4pt">{_esc(d)}</span>' for d in b.get("data_classes", []))
            pwn_color = "#dc2626" if b.get("pwn_count", 0) > 1_000_000 else "#d97706" if b.get("pwn_count", 0) > 100_000 else "#374151"
            breach_rows += f"""<tr>
              <td style="padding:5pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top;white-space:nowrap">
                <span style="font-weight:700;color:#111827">{_esc(b['name'])}</span>{verified}{sensitive}
              </td>
              <td style="padding:5pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top;white-space:nowrap;color:{pwn_color};font-weight:600">{count}</td>
              <td style="padding:5pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top;white-space:nowrap;color:#6b7280">{_esc(b.get('breach_date',''))}</td>
              <td style="padding:5pt 8pt;border-bottom:1px solid #f3f4f6;vertical-align:top">{pills}</td>
            </tr>"""
        breach_html = f"""
        <p style="font-size:8pt;color:#dc2626;font-weight:700;margin-bottom:6pt">
          {len(breaches)} breach{"es" if len(breaches)!=1 else ""} found — {total_records:,} total records exposed
        </p>
        <table>
          <tr style="background:#f9fafb">
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Breach</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Records</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Date</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Data Exposed</th>
          </tr>{breach_rows}
        </table>"""
    else:
        breach_html = '<p style="color:#9ca3af;font-style:italic;font-size:8pt">No known breaches found for this domain.</p>'

    breach_section = f"""<section>
      <div class="section-header" style="border-left:4px solid #dc2626">
        <h2>Breach Intelligence</h2>
      </div>
      <div style="padding:6pt 8pt">{breach_html}</div>
    </section>"""

    # Open ports section
    _RISK_COLORS = {"critical": "#dc2626", "high": "#d97706", "medium": "#6b7280", "info": "#16a34a"}
    if ports:
        risky = [p for p in ports if p.get("risk") != "info"]
        summary_line = f'{len(ports)} open port{"s" if len(ports) != 1 else ""} found{f" — {len(risky)} noteworthy" if risky else ""}.'
        port_rows = "".join(
            f"""<tr>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;font-weight:700;color:#1a56db">{p['port']}</td>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6">{_esc(p['service'])}</td>
              <td style="padding:4pt 8pt;border-bottom:1px solid #f3f4f6;font-weight:700;color:{_RISK_COLORS.get(p.get('risk','info'), '#6b7280')}">{_esc(p.get('risk','').upper())}</td>
            </tr>"""
            for p in ports
        )
        ports_html = f"""<p style="font-size:8pt;color:#6b7280;margin-bottom:6pt">{_esc(summary_line)}</p>
        <table>
          <tr style="background:#f9fafb">
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600;width:50pt">Port</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Service</th>
            <th style="padding:4pt 8pt;text-align:left;font-size:7.5pt;color:#6b7280;font-weight:600">Risk</th>
          </tr>{port_rows}
        </table>"""
    else:
        ports_html = '<p style="color:#9ca3af;font-style:italic;font-size:8pt">No exposed ports detected on scanned common ports.</p>'

    ports_section = f"""<section>
      <div class="section-header" style="border-left:4px solid #2563eb">
        <h2>Exposed Ports</h2>
      </div>
      <div style="padding:6pt 8pt">{ports_html}</div>
    </section>"""

    # Security headers grade section
    _SEC_HEADERS_PDF = [
        ("strict-transport-security", "HSTS",                    30, "forces HTTPS"),
        ("content-security-policy",   "Content-Security-Policy", 25, "prevents XSS"),
        ("x-frame-options",           "X-Frame-Options",         15, "prevents clickjacking"),
        ("x-content-type-options",    "X-Content-Type-Options",  15, "prevents MIME sniffing"),
        ("referrer-policy",           "Referrer-Policy",         10, "controls referrer info"),
        ("permissions-policy",        "Permissions-Policy",       5, "controls browser features"),
    ]
    _GRADE_COLORS = {"A+": "#16a34a", "A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#dc2626"}

    h_lower = {k.lower(): True for k in (headers or {}).keys()}
    sec_score = sum(w for key, _, w, _ in _SEC_HEADERS_PDF if key in h_lower)
    if sec_score == 100:   sec_grade = "A+"
    elif sec_score >= 80:  sec_grade = "A"
    elif sec_score >= 60:  sec_grade = "B"
    elif sec_score >= 40:  sec_grade = "C"
    elif sec_score >= 20:  sec_grade = "D"
    else:                  sec_grade = "F"
    grade_color = _GRADE_COLORS.get(sec_grade, "#6b7280")

    def _csp_report_only(key):
        return key == "content-security-policy" and key not in h_lower \
               and "content-security-policy-report-only" in h_lower

    check_rows = "".join(
        f"""<tr>
          <td style="padding:3pt 8pt;border-bottom:1px solid #f3f4f6;width:14pt;
              color:{'#16a34a' if key in h_lower else '#d97706' if _csp_report_only(key) else '#dc2626'};
              font-weight:700">{'✓' if key in h_lower else '⚠' if _csp_report_only(key) else '✗'}</td>
          <td style="padding:3pt 8pt;border-bottom:1px solid #f3f4f6;font-weight:600">{_esc(name)}</td>
          <td style="padding:3pt 8pt;border-bottom:1px solid #f3f4f6;color:#6b7280;font-size:7.5pt">
            {_esc(desc)}{' (report-only — not enforced)' if _csp_report_only(key) else ''}</td>
          <td style="padding:3pt 8pt;border-bottom:1px solid #f3f4f6;color:#6b7280;font-size:7.5pt;text-align:right">{weight}pts</td>
        </tr>"""
        for key, name, weight, desc in _SEC_HEADERS_PDF
    )
    headers_sec_html = f"""
    <div style="display:flex;align-items:flex-start;gap:16pt;padding:6pt 8pt">
      <div style="font-size:28pt;font-weight:900;color:{grade_color};line-height:1;min-width:30pt;text-align:center">{_esc(sec_grade)}</div>
      <div style="flex:1">
        <p style="font-size:8pt;color:#6b7280;margin-bottom:6pt">Score: {sec_score} / 100</p>
        <table>{check_rows}</table>
      </div>
    </div>"""

    headers_sec_section = f"""<section>
      <div class="section-header" style="border-left:4px solid #7e3af2">
        <h2>Security Headers</h2>
      </div>
      {headers_sec_html}
    </section>"""

    errors_section = ""
    if errors:
        errors_section = _section("Lookup Errors", _rows(errors, skip_empty=False), color="#e02424")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
  @page {{
    size: A4;
    margin: 18mm 16mm 18mm 16mm;
    @bottom-center {{
      content: "ReconLens — Confidential — Page " counter(page) " of " counter(pages);
      font-family: 'Courier New', monospace;
      font-size: 8pt;
      color: #6b7280;
    }}
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Courier New', Courier, monospace;
    font-size: 9pt;
    color: #111827;
    background: #fff;
    line-height: 1.5;
  }}

  /* ── Cover header ── */
  .cover {{
    border-bottom: 2px solid #1a56db;
    padding-bottom: 12pt;
    margin-bottom: 18pt;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .cover-left h1 {{
    font-size: 22pt;
    font-weight: 700;
    color: #1a56db;
    letter-spacing: -0.5px;
  }}
  .cover-left .subtitle {{
    font-size: 9pt;
    color: #6b7280;
    margin-top: 2pt;
  }}
  .cover-right {{
    text-align: right;
    font-size: 8pt;
    color: #6b7280;
    line-height: 1.8;
  }}

  /* ── Target box ── */
  .target-box {{
    background: #f0f4ff;
    border: 1px solid #c3d3fb;
    border-radius: 6pt;
    padding: 10pt 14pt;
    margin-bottom: 18pt;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .target-box .label {{
    font-size: 8pt;
    color: #6b7280;
    text-transform: uppercase;
    letter-spacing: 0.8px;
  }}
  .target-box .domain {{
    font-size: 16pt;
    font-weight: 700;
    color: #1a56db;
    margin-top: 2pt;
  }}
  .target-box .badge {{
    background: #1a56db;
    color: #fff;
    font-size: 7.5pt;
    padding: 3pt 8pt;
    border-radius: 4pt;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }}

  /* ── Sections ── */
  section {{
    margin-bottom: 16pt;
    break-inside: avoid;
  }}
  .section-header {{
    padding: 5pt 10pt;
    background: #f9fafb;
    margin-bottom: 0;
  }}
  .section-header h2 {{
    font-size: 9pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: #374151;
  }}

  /* ── Tables ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 8.5pt;
  }}
  td {{
    padding: 4pt 8pt;
    vertical-align: top;
    border-bottom: 1px solid #f3f4f6;
  }}
  tr:last-child td {{ border-bottom: none; }}
  td.key {{
    width: 160pt;
    color: #6b7280;
    font-weight: 600;
    white-space: nowrap;
    padding-right: 12pt;
  }}
  td.empty {{
    color: #9ca3af;
    font-style: italic;
  }}
  .val {{ color: #111827; word-break: break-all; }}
  .tag {{
    display: inline-block;
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 3pt;
    color: #1d4ed8;
    font-size: 7.5pt;
    padding: 1pt 5pt;
    margin: 1pt 2pt 1pt 0;
  }}

  /* ── IP Reputation ── */
  .ip-block {{
    border: 1px solid #e5e7eb;
    border-radius: 4pt;
    margin-bottom: 8pt;
    overflow: hidden;
  }}
  .ip-header {{
    background: #f9fafb;
    border-bottom: 1px solid #e5e7eb;
    padding: 4pt 8pt;
    display: flex;
    align-items: center;
    gap: 6pt;
    flex-wrap: wrap;
  }}
  .ip-addr  {{ font-weight: 700; color: #1a56db; font-size: 9pt; }}
  .ip-cc    {{ background: #e5e7eb; border-radius: 2pt; color: #6b7280; font-size: 7pt; font-weight: 700; padding: 1pt 4pt; }}
  .ip-badges {{ display: flex; gap: 3pt; flex-wrap: wrap; }}
  .rep-badge {{ border-radius: 3pt; font-size: 7pt; font-weight: 700; padding: 1pt 5pt; }}
  .rep-ok      {{ background: #dcfce7; border: 1px solid #86efac; color: #166534; }}
  .rep-warn    {{ background: #fef9c3; border: 1px solid #fde047; color: #854d0e; }}
  .rep-danger  {{ background: #fee2e2; border: 1px solid #fca5a5; color: #991b1b; }}
  .rep-neutral {{ background: #f3f4f6; border: 1px solid #d1d5db; color: #6b7280; }}

  /* ── Tech stack ── */
  .tech-pill {{
    display: inline-block;
    border-radius: 3pt;
    font-size: 7.5pt;
    font-weight: 700;
    padding: 1pt 5pt;
    margin: 1pt 2pt 1pt 0;
  }}

  /* ── CT subdomains ── */
  .ct-count {{
    font-size: 8pt;
    color: #6b7280;
    margin-bottom: 5pt;
  }}

  /* ── SSL badges ── */
  .ssl-badge {{
    display: inline-block;
    border-radius: 4pt;
    font-size: 8pt;
    font-weight: 700;
    padding: 2pt 7pt;
    margin-bottom: 6pt;
  }}
  .ssl-ok       {{ background: #dcfce7; color: #166534; border: 1px solid #86efac; }}
  .ssl-warn     {{ background: #fef9c3; color: #854d0e; border: 1px solid #fde047; }}
  .ssl-critical {{ background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }}
  .ssl-expired  {{ background: #fee2e2; color: #991b1b; border: 1px solid #f87171; font-weight: 900; }}

  /* ── Disclaimer ── */
  .disclaimer {{
    margin-top: 20pt;
    padding-top: 10pt;
    border-top: 1px solid #e5e7eb;
    font-size: 7.5pt;
    color: #9ca3af;
    line-height: 1.6;
  }}
</style>
</head>
<body>

  <div class="cover">
    <div class="cover-left">
      <h1>ReconLens</h1>
      <div class="subtitle">Open-Source Intelligence Report</div>
    </div>
    <div class="cover-right">
      <div>Generated: {generated}</div>
      <div>Classification: CONFIDENTIAL</div>
    </div>
  </div>

  <div class="target-box">
    <div>
      <div class="label">Target Domain</div>
      <div class="domain">{domain}</div>
    </div>
    <div class="badge">Passive Recon</div>
  </div>

  {_section("DNS Records", dns_html)}
  {_section("WHOIS Registration Data", _rows(whois), color="#047857")}
  <section>
    <div class="section-header" style="border-left:4px solid #d97706">
      <h2>SSL / TLS Certificate</h2>
    </div>
    {ssl_html}
  </section>
  <section>
    <div class="section-header" style="border-left:4px solid #6d28d9">
      <h2>Tech Stack Fingerprint</h2>
    </div>
    <div style="padding:6pt 8pt">{tech_html}</div>
  </section>
  <section>
    <div class="section-header" style="border-left:4px solid #dc2626">
      <h2>IP Reputation &amp; Geolocation</h2>
    </div>
    <div style="padding:6pt 8pt">{ip_blocks_html}</div>
  </section>
  {ports_section}
  <section>
    <div class="section-header" style="border-left:4px solid #0891b2">
      <h2>Certificate Transparency — Subdomains</h2>
    </div>
    <div style="padding:6pt 8pt">{ct_html}</div>
  </section>
  {headers_sec_section}
  {_section("HTTP Response Headers", _rows(headers), color="#7e3af2")}
  {takeover_section}
  {breach_section}
  {errors_section}

  <div class="disclaimer">
    This report was generated automatically by ReconLens using only publicly available data sources.
    All information is provided for informational and defensive security purposes only.
    The operator assumes no liability for misuse of this data.
  </div>

</body>
</html>"""


def generate_pdf(data: dict) -> bytes:
    html = build_html(data)
    return weasyprint.HTML(string=html).write_pdf()
