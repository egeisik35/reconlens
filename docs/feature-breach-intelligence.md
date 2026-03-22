# Feature: Breach Intelligence (HIBP)

## What it does

Checks whether the target domain has appeared in any known data breaches using
the HaveIBeenPwned public API. Shows breach names, dates, record counts, and
what types of data were exposed (passwords, emails, phone numbers, etc.).

## API used

`GET https://haveibeenpwned.com/api/v3/breaches?domain={domain}`

- **Free, no API key required** for domain-level breach lookups
- Returns all known breaches that affected accounts registered at the target domain
- Rate limit: 1 request/1.5s (handled via a short sleep)

## What each breach record contains

| Field | Description |
|---|---|
| `Name` | Breach identifier (e.g. "Adobe") |
| `Domain` | Domain that was breached |
| `BreachDate` | Date the breach occurred |
| `PwnCount` | Number of accounts compromised |
| `DataClasses` | Types of data exposed (Passwords, Email addresses, etc.) |
| `IsVerified` | Whether HIBP has verified the breach as real |
| `IsSensitive` | Whether the breach is sensitive (adult sites, etc.) |
| `Description` | Human-readable summary of the breach |

## Display

- Show total breach count and total records exposed at the top
- List each breach as a card with: name, date, record count, data types as pills
- Color code by severity: >1M records = red, >100k = yellow, rest = neutral
- Unverified breaches shown with a grey "Unverified" badge
- Sensitive breaches shown with name only, no description

## Scope / Limits

- Domain-level only (free tier) — no per-email checking (requires $3.50/mo API key)
- Skips breaches where `IsSensitive = true` description (show name/date only)
- Timeout: 8 seconds
- On failure (rate limit, network error): return empty list silently, log warning

## Files to change

| File | Change |
|---|---|
| `backend/breach.py` | New file — HIBP fetch + normalisation |
| `backend/osint.py` | Call `fetch_breaches()` from `run_all()`, add `breaches` key |
| `backend/pdf_gen.py` | Add Breach Intelligence section |
| `frontend/index.html` | Add breach card |
| `frontend/app.js` | `renderBreaches()` function |
| `frontend/style.css` | Breach card styles |
| `README.md` | Update feature table |

## Acceptance criteria
- [ ] Breaches returned for a domain known to be in HIBP (e.g. adobe.com)
- [ ] Empty result (not an error) for a domain with no known breaches
- [ ] Record count formatted with commas (e.g. 152,445,165)
- [ ] Data type pills rendered per breach
- [ ] Results shown in UI card and PDF export
