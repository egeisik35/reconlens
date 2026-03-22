# OSINT Aggregator

A professional passive reconnaissance platform for security analysts, pentesters, and consultants. Enter a domain and get a structured intelligence report covering DNS, WHOIS, SSL/TLS, tech stack, IP reputation, Certificate Transparency logs, and HTTP headers — with PDF export and automated domain monitoring with email alerts.

---

## Features

| Module | What it collects |
|---|---|
| **DNS Records** | A, MX, NS, TXT |
| **WHOIS** | Registrar, creation/expiry dates, name servers, org, country |
| **SSL / TLS** | Subject CN, issuer, validity window, days until expiry, serial, SANs |
| **Tech Stack** | CDN, web server, CMS, language/runtime, JS frameworks, analytics, WAF, hosting — 60+ signatures |
| **IP Reputation** | Geolocation, ISP, ASN, proxy/VPN flag, hosting/DC flag, Spamhaus + SpamCop DNSBL |
| **Certificate Transparency** | All subdomains ever issued a cert via crt.sh |
| **HTTP Headers** | Full response header set |
| **PDF Export** | Branded A4 report with expiry banners, tech badges, page numbers |
| **Domain Monitoring** | 24h checks — email alerts on DNS changes, new subdomains, SSL expiry, tech stack changes |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Uvicorn |
| OSINT | dnspython, python-whois, requests, built-in ssl/socket |
| PDF | WeasyPrint (HTML → PDF via Cairo/Pango) |
| Monitoring | APScheduler (24h background jobs), SQLite |
| Email | Resend API |
| Rate limiting | slowapi |
| Frontend | Vanilla HTML/CSS/JS, dark mode, no framework dependencies |

---

## Running Locally

```bash
# 1. Create virtualenv
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and add your RESEND_API_KEY

# 4. Start the server
cd backend
uvicorn main:app --reload
```

Open `http://localhost:8000`.

---

## Environment Variables

Copy `.env.example` to `.env` and fill in the values:

| Variable | Required | Description |
|---|---|---|
| `RESEND_API_KEY` | Yes (for alerts) | API key from resend.com |
| `FROM_EMAIL` | No | Sender address (default: `onboarding@resend.dev` for testing) |
| `DB_PATH` | No | Absolute path to SQLite database (default: `backend/monitors.db`) |
| `BASE_URL` | No | Public URL of your deployment (used in unsubscribe links) |

---

## Docker

```bash
# Build
docker build -t osint-aggregator .

# Run (pass env vars at runtime — never bake secrets into the image)
docker run -p 8000:8000 \
  -e RESEND_API_KEY=re_your_key \
  -e FROM_EMAIL=alerts@yourdomain.com \
  -e BASE_URL=https://yourdomain.com \
  -v /data/osint:/app/backend \
  osint-aggregator
```

The `-v` mount persists the SQLite database across container restarts.

The Dockerfile installs all OS-level WeasyPrint dependencies (`libpango`, `libcairo`, `libgdk-pixbuf`, `fonts-liberation`) on Debian slim.

---

## API Reference

### `POST /api/lookup`
Run a full OSINT scan.
```json
{ "domain": "example.com" }
```
Returns structured JSON with `dns`, `whois`, `ssl`, `tech_stack`, `ip_reputation`, `ct`, `headers`, `errors`.

### `POST /api/export-pdf`
Generate a PDF report from a previous lookup result.
Accepts the same JSON shape as the lookup response. Returns `application/pdf`.

### `POST /api/watch`
Subscribe to domain change monitoring.
```json
{ "domain": "example.com", "email": "you@example.com" }
```

### `GET /api/unwatch?id={monitor_id}`
Unsubscribe from alerts (linked from every alert email).

---

## Monitoring — What triggers an alert

- Any DNS record (A/MX/NS/TXT) added or removed
- SSL certificate replaced (subject CN, issuer, or expiry date changed)
- SSL expiry ≤ 30 days
- New subdomain discovered in Certificate Transparency logs
- Tech stack change (e.g. CDN switched from Cloudflare to Fastly, CMS detected/removed)

Checks run every 24 hours via APScheduler. On first watch, a baseline snapshot is stored. All subsequent runs are diffed against that baseline.

---

## Security

- **SSRF protection** — all outbound connections validate the resolved IP against RFC1918, loopback, link-local, and reserved ranges before connecting
- **Input validation** — domain regex-validated and sanitised on every endpoint; email validated on watch endpoint
- **Rate limiting** — 10 req/min per IP on lookup/export, 3 req/min on watch
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-XSS-Protection` on all responses
- **Error sanitisation** — raw exceptions logged server-side only; clients receive generic messages
- **Output escaping** — all user-derived data HTML-escaped before PDF rendering
- **Filename sanitisation** — `Content-Disposition` filename stripped of unsafe characters

---

## Project Structure

```
├── Dockerfile
├── .env.example
├── REQUIREMENTS.md          # Full product requirements doc
├── README.md
├── backend/
│   ├── main.py              # FastAPI app, all endpoints, lifespan handler
│   ├── osint.py             # OSINT fetchers + SSRF guard
│   ├── techstack.py         # Tech stack signature database + detection engine
│   ├── pdf_gen.py           # WeasyPrint HTML→PDF renderer
│   ├── database.py          # SQLite schema + connection helper
│   ├── monitor.py           # Snapshot engine + diff logic
│   ├── mailer.py            # Resend email sender (confirmation + alerts)
│   ├── scheduler.py         # APScheduler 24h background job
│   └── requirements.txt
└── frontend/
    ├── index.html           # App shell
    ├── style.css            # Dark-mode design system
    └── app.js               # Fetch, rendering, watch form logic
```

---

## Roadmap

- [ ] User accounts + magic-link auth
- [ ] Historical diff — show what changed between any two dates
- [ ] Bulk domain CSV upload
- [ ] API key access for programmatic lookups
- [ ] Custom report branding (white-label PDF for Pro users)

---

## License

Proprietary — all rights reserved.
