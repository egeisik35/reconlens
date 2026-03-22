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
    headers = data.get("headers", {})
    errors = data.get("errors", {})

    # DNS: filter empty record types
    dns_filtered = {k: v for k, v in dns.items() if v}
    dns_html = _rows(dns_filtered, skip_empty=False) if dns_filtered else \
        "<tr><td colspan='2' class='empty'>No DNS records found</td></tr>"

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
      content: "OSINT Aggregator — Confidential — Page " counter(page) " of " counter(pages);
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
      <h1>OSINT Aggregator</h1>
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
  {_section("HTTP Response Headers", _rows(headers), color="#7e3af2")}
  {errors_section}

  <div class="disclaimer">
    This report was generated automatically by OSINT Aggregator using only publicly available data sources.
    All information is provided for informational and defensive security purposes only.
    The operator assumes no liability for misuse of this data.
  </div>

</body>
</html>"""


def generate_pdf(data: dict) -> bytes:
    html = build_html(data)
    return weasyprint.HTML(string=html).write_pdf()
