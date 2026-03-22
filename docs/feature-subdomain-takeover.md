# Feature: Subdomain Takeover Detection

## What it does

For every subdomain discovered via Certificate Transparency logs, check whether it
is vulnerable to a subdomain takeover — i.e. the DNS record points to an external
service that is no longer claimed by the target.

## Why it matters

A dangling CNAME pointing at an unclaimed GitHub Pages site, S3 bucket, or Heroku
app can be registered by an attacker, allowing them to serve content under the
victim's subdomain. This is a real, exploitable vulnerability commonly found during
bug bounty and pentesting engagements.

## Detection approach

### Step 1 — DNS resolution
For each subdomain:
- Attempt to resolve the CNAME chain via dnspython
- If the subdomain returns NXDOMAIN (no DNS record at all) → flag as "Dangling DNS"

### Step 2 — Service fingerprinting
Match the final CNAME target against a list of known vulnerable service patterns:

| Service | CNAME pattern | Unclaimed response signature |
|---|---|---|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" |
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-website-*.amazonaws.com` | "NoSuchBucket" / "The specified bucket does not exist" |
| Heroku | `*.herokuapp.com` | "No such app" |
| Netlify | `*.netlify.app` | "Not Found - Request ID" |
| Shopify | `*.myshopify.com` | "Sorry, this shop is currently unavailable" |
| Fastly | any | "Fastly error: unknown domain" |
| Ghost | `*.ghost.io` | "The thing you were looking for is no longer here" |
| Surge.sh | `*.surge.sh` | "project not found" |
| Azure | `*.azurewebsites.net` | "404 Web Site not found" |
| Readme.io | `*.readme.io` | "Project doesnt exist" |
| Zendesk | `*.zendesk.com` | "Help Center Closed" |
| Tumblr | `*.tumblr.com` | "Whatever you were looking for doesn't live here" |
| Pantheon | `*.pantheonsite.io` | "The gods are wise, but do not know of the site" |
| WPEngine | `*.wpengine.com` | "The site you were looking for couldn't be found" |

### Step 3 — HTTP probe
If a CNAME matches a known service pattern, make an HTTP GET request to
`https://{subdomain}` and check the response body for the unclaimed signature.
Only flag as vulnerable if the signature is found.

### Step 4 — Result
Each finding includes:
- `subdomain` — the affected subdomain
- `cname` — where the CNAME points
- `service` — matched service name
- `status` — `"vulnerable"` / `"dangling"` / `"check_failed"`
- `detail` — human-readable explanation

## Severity
- `vulnerable` (confirmed unclaimed service) → HIGH
- `dangling` (NXDOMAIN) → MEDIUM

## Scope / Limits
- Only checks subdomains already discovered via CT logs (passive, no brute force)
- Max 20 subdomains probed per lookup (avoid abuse / slow requests)
- HTTP probe timeout: 5 seconds per subdomain
- All outbound requests pass through existing SSRF guard

## Files to change

| File | Change |
|---|---|
| `backend/takeover.py` | New file — fingerprints + detection logic |
| `backend/osint.py` | Call `check_takeovers()` from `run_all()`, add `takeover` key to result |
| `backend/pdf_gen.py` | Add Takeover Risks section |
| `frontend/index.html` | Add takeover card |
| `frontend/app.js` | `renderTakeover()` function |
| `frontend/style.css` | Takeover card styles (HIGH/MEDIUM severity badges) |
| `README.md` | Update feature table |

## Acceptance criteria
- [ ] Dangling DNS (NXDOMAIN) subdomains are detected and flagged MEDIUM
- [ ] Confirmed unclaimed services are flagged HIGH with service name
- [ ] No false positives on a healthy domain (e.g. google.com)
- [ ] Max 20 subdomains probed, gracefully skips the rest
- [ ] Results appear in UI card and PDF export
- [ ] SSRF guard applies to all HTTP probes
