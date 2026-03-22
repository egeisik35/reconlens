# OSINT Data Aggregator — Requirements

## Project Overview
A web application that accepts a target domain name and returns aggregated public intelligence including DNS records, WHOIS data, and HTTP response headers.

## Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Frontend  | HTML5, CSS3, Vanilla JavaScript     |
| Backend   | Python 3.10+, FastAPI               |
| OSINT     | dnspython, python-whois, requests   |
| Server    | Uvicorn (ASGI)                      |

## Functional Requirements

1. User enters a target domain in a text input field and submits.
2. The frontend sends a POST request to the backend API.
3. The backend runs OSINT lookups:
   - **DNS Records**: A, MX, NS, TXT records via `dnspython`
   - **WHOIS Data**: registrar, creation/expiry dates, name servers via `python-whois`
   - **HTTP Headers**: server, content-type, security headers via `requests`
4. Results are returned as structured JSON and rendered cleanly in the UI.

## Non-Functional Requirements

- Dark mode UI (default), minimalist design
- Results displayed in collapsible sections per data category
- Loading state shown while backend processes the request
- Error messages shown on failed lookups
- No authentication required (public tool)

## Project Structure

```
my-saas-app/
├── REQUIREMENTS.md
├── backend/
│   ├── main.py            # FastAPI app + API routes
│   ├── osint.py           # OSINT data-fetching logic
│   └── requirements.txt   # Python dependencies
└── frontend/
    ├── index.html         # App shell
    ├── style.css          # Dark-mode styles
    └── app.js             # Fetch logic + DOM rendering
```

## API Contract

### `POST /api/lookup`

**Request body:**
```json
{ "domain": "example.com" }
```

**Response body:**
```json
{
  "domain": "example.com",
  "dns": {
    "A": ["93.184.216.34"],
    "MX": ["..."],
    "NS": ["..."],
    "TXT": ["..."]
  },
  "whois": {
    "registrar": "...",
    "creation_date": "...",
    "expiration_date": "...",
    "name_servers": ["..."],
    "status": "..."
  },
  "headers": {
    "Server": "...",
    "Content-Type": "...",
    "X-Frame-Options": "..."
  },
  "errors": {}
}
```
