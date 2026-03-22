# OSINT Aggregator

A professional-grade passive reconnaissance tool for security analysts, pentesters, and consultants. Enter a domain and receive a structured intelligence report covering DNS, WHOIS, SSL/TLS, Certificate Transparency logs, and HTTP headers — exportable as a branded PDF.

## Features

| Module | Data Collected |
|---|---|
| **DNS Records** | A, MX, NS, TXT |
| **WHOIS** | Registrar, creation/expiry dates, name servers, org, country |
| **SSL / TLS** | Subject CN, issuer, validity window, days until expiry, serial, SANs |
| **Certificate Transparency** | All subdomains ever issued a cert via `crt.sh` |
| **HTTP Headers** | Full response header set (server, security headers, content-type, etc.) |
| **PDF Export** | Branded A4 report with expiry banners, tagged subdomain lists, page numbers |

## Tech Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn
- **OSINT**: `dnspython`, `python-whois`, `requests`, built-in `ssl`/`socket`
- **PDF**: WeasyPrint (HTML → PDF via Cairo/Pango)
- **Rate limiting**: slowapi
- **Frontend**: Vanilla HTML/CSS/JS, dark mode, no framework

## Security

- **SSRF protection**: all outbound connections check the resolved IP against RFC1918, loopback, link-local, and reserved ranges before connecting
- **Input validation**: domain regex-validated and sanitised on every endpoint
- **Rate limiting**: 10 requests/minute per IP on both API endpoints
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-XSS-Protection` on all responses
- **Error sanitisation**: raw exceptions are logged server-side only; clients receive generic messages
- **Output escaping**: all user-derived data is HTML-escaped before PDF rendering

## Running Locally

```bash
# 1. Create and activate a virtualenv
python -m venv venv
source venv/bin/activate

# 2. Install Python dependencies
pip install -r backend/requirements.txt

# 3. Start the server
cd backend
uvicorn main:app --reload
```

Open `http://localhost:8000`.

## Docker

```bash
docker build -t osint-aggregator .
docker run -p 8000:8000 osint-aggregator
```

The Dockerfile installs all OS-level WeasyPrint dependencies (`libpango`, `libcairo`, `libgdk-pixbuf`, `fonts-liberation`) on Debian slim.

## Project Structure

```
├── Dockerfile
├── REQUIREMENTS.md          # Full product requirements
├── README.md
├── backend/
│   ├── main.py              # FastAPI app, rate limiting, security headers
│   ├── osint.py             # OSINT fetchers + SSRF guard
│   ├── pdf_gen.py           # WeasyPrint HTML→PDF renderer
│   └── requirements.txt
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## API

### `POST /api/lookup`
```json
{ "domain": "example.com" }
```
Returns structured JSON with `dns`, `whois`, `ssl`, `ct`, `headers`, and `errors` keys.

### `POST /api/export-pdf`
Accepts the same JSON shape as a lookup response. Returns `application/pdf`.

## License

Proprietary — all rights reserved.
