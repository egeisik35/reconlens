# Feature: Enterprise Polish — Summary Dashboard

## Goal

Make the tool feel like a professional product, not a dev project.
Security managers and clients should be able to see critical findings
at a glance without opening every accordion.

## Changes

### 1. Top-level summary card
Appears immediately below the domain header, above all accordions.
Shows color-coded status rows derived from existing data — no new API calls.

| Check | Green | Yellow | Red |
|---|---|---|---|
| SSL Certificate | Valid, >30 days | Expiring <30 days | Expired / missing |
| Blacklists | Clean on all | — | Listed on any DNSBL |
| DMARC Record | TXT record present | — | Missing _dmarc record |
| SPF Record | TXT record present | — | Missing SPF |
| Data Breaches | None found | — | Any breach found |
| Subdomain Takeover | None found | Potential (check_failed) | Confirmed vulnerable |
| Subdomains | — | — | Count shown (info) |

### 2. Status dot on accordion headers
Each card title gets a small colored dot indicator on the right side:
- 🟢 green = all good
- 🟡 yellow = warning
- 🔴 red = issue found
- ⚫ grey = no data

### 3. Move Watch/Monitor button up
Add a "Watch" button next to "Export PDF" in the result header bar.
Keep the full watch card at the bottom for the email input form.
The top button scrolls down to the watch card.

## Implementation

All logic is frontend-only (JS). Data is already in `lastResults`.

### Summary checks (app.js)

```
checkSsl(data.ssl)         → { status: "ok"|"warn"|"error"|"none", label }
checkBlacklists(data.ip_reputation) → { status, label }
checkDmarc(data.dns)       → { status, label }
checkSpf(data.dns)         → { status, label }
checkBreaches(data.breaches) → { status, label }
checkTakeover(data.takeover) → { status, label }
checkSubdomains(data.ct)   → { status: "info", label }
```

## Files to change

| File | Change |
|---|---|
| `frontend/index.html` | Add `#summary-card` div, add watch shortcut button |
| `frontend/app.js` | `buildSummary()` + all check functions, call after lookup |
| `frontend/style.css` | Summary card styles, status dots on headers |

No backend changes needed.

## Acceptance criteria
- [ ] Summary card visible immediately after lookup, before accordions
- [ ] All 7 checks correctly derive status from existing result data
- [ ] Accordion headers show a status dot matching the summary
- [ ] Watch button in header scrolls to watch card
- [ ] Works correctly on mobile (wraps gracefully)
