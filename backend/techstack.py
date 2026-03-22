"""
Tech stack fingerprinting via HTTP header + HTML body analysis.
Rule-based, zero external dependencies.
"""
import re
import requests

# ── Signature database ────────────────────────────────────────────────────────
# Each entry: {category, headers, body, cookies}
# headers/cookies: {header_name: regex}   (case-insensitive match on value)
# body:            [regex, ...]            (case-insensitive match on HTML)

_SIGS: dict = {
    # ── CDN ───────────────────────────────────────────────────────────────────
    "Cloudflare": {
        "category": "cdn",
        "headers": {"cf-ray": r".", "server": r"cloudflare"},
        "cookies": {"__cf_bm": r".", "__cfduid": r"."},
    },
    "Fastly": {
        "category": "cdn",
        "headers": {"x-fastly-request-id": r".", "x-served-by": r"cache-"},
    },
    "AWS CloudFront": {
        "category": "cdn",
        "headers": {"x-amz-cf-id": r".", "via": r"CloudFront"},
    },
    "Varnish": {
        "category": "cdn",
        "headers": {"x-varnish": r".", "via": r"varnish"},
    },
    "Akamai": {
        "category": "cdn",
        "headers": {"x-akamai-transformed": r".", "x-check-cacheable": r"."},
    },
    "jsDelivr": {
        "category": "cdn",
        "headers": {"server": r"jsDelivr"},
    },

    # ── Web server ────────────────────────────────────────────────────────────
    "Nginx": {
        "category": "web_server",
        "headers": {"server": r"nginx"},
    },
    "Apache": {
        "category": "web_server",
        "headers": {"server": r"Apache"},
    },
    "IIS": {
        "category": "web_server",
        "headers": {"server": r"Microsoft-IIS"},
    },
    "LiteSpeed": {
        "category": "web_server",
        "headers": {"server": r"LiteSpeed"},
    },
    "OpenResty": {
        "category": "web_server",
        "headers": {"server": r"openresty"},
    },
    "Caddy": {
        "category": "web_server",
        "headers": {"server": r"Caddy"},
    },
    "Gunicorn": {
        "category": "web_server",
        "headers": {"server": r"gunicorn"},
    },

    # ── CMS / Platform ────────────────────────────────────────────────────────
    "WordPress": {
        "category": "cms",
        "headers": {"x-pingback": r"xmlrpc\.php", "link": r"wp-json"},
        "body": [r"/wp-content/", r"/wp-includes/", r"wp-emoji"],
    },
    "Drupal": {
        "category": "cms",
        "headers": {"x-generator": r"Drupal", "x-drupal-cache": r"."},
        "body": [r"Drupal\.settings", r"/sites/default/files/"],
    },
    "Joomla": {
        "category": "cms",
        "body": [r"/media/joomla_", r"content=\"Joomla"],
    },
    "Shopify": {
        "category": "cms",
        "headers": {"x-shopify-stage": r"."},
        "body": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "cookies": {"_shopify_y": r"."},
    },
    "Wix": {
        "category": "cms",
        "body": [r"static\.wixstatic\.com", r"wix-bolt"],
    },
    "Squarespace": {
        "category": "cms",
        "body": [r"static\.squarespace\.com", r"squarespace-cdn\.com"],
    },
    "Ghost": {
        "category": "cms",
        "headers": {"x-ghost-cache-status": r"."},
        "body": [r"content=\"Ghost"],
    },
    "Webflow": {
        "category": "cms",
        "headers": {"x-powered-by": r"Webflow"},
        "body": [r"assets\.website-files\.com", r"webflow\.com/css"],
    },
    "Magento": {
        "category": "cms",
        "body": [r"Mage\.Cookies", r"/skin/frontend/"],
        "cookies": {"MAGE_CACHE_SESSID": r"."},
    },
    "PrestaShop": {
        "category": "cms",
        "body": [r"prestashop", r"/modules/ps_"],
    },
    "HubSpot CMS": {
        "category": "cms",
        "body": [r"hs-scripts\.com", r"hubspot\.com/hs/"],
    },

    # ── Language / Runtime ────────────────────────────────────────────────────
    "PHP": {
        "category": "language",
        "headers": {"x-powered-by": r"PHP"},
        "cookies": {"PHPSESSID": r"."},
    },
    "ASP.NET": {
        "category": "language",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"."},
        "cookies": {"ASP.NET_SessionId": r"."},
    },
    "Node.js": {
        "category": "language",
        "headers": {"x-powered-by": r"Express|Node"},
    },
    "Python": {
        "category": "language",
        "headers": {"server": r"gunicorn|uvicorn|tornado|django"},
    },
    "Ruby": {
        "category": "language",
        "headers": {"x-powered-by": r"Phusion Passenger", "server": r"Passenger"},
    },
    "Java": {
        "category": "language",
        "headers": {"x-powered-by": r"JSP|Servlet|Tomcat|JBoss"},
        "cookies": {"JSESSIONID": r"."},
    },

    # ── JS Frameworks ─────────────────────────────────────────────────────────
    "React": {
        "category": "js_framework",
        "body": [r"react\.production\.min\.js", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    },
    "Next.js": {
        "category": "js_framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "body": [r"__NEXT_DATA__", r"/_next/static/"],
    },
    "Vue.js": {
        "category": "js_framework",
        "body": [r"vue\.runtime\.min\.js", r"vue\.min\.js", r"__vue__"],
    },
    "Nuxt.js": {
        "category": "js_framework",
        "body": [r"__NUXT__", r"nuxt\.min\.js", r"/_nuxt/"],
    },
    "Angular": {
        "category": "js_framework",
        "body": [r"ng-version=", r"angular\.min\.js", r"@angular/core"],
    },
    "jQuery": {
        "category": "js_framework",
        "body": [r"jquery\.min\.js", r"jquery-\d+\.\d+", r"jQuery v\d"],
    },
    "Svelte": {
        "category": "js_framework",
        "body": [r"__svelte", r"svelte/"],
    },
    "Alpine.js": {
        "category": "js_framework",
        "body": [r"alpinejs", r"x-data="],
    },
    "Gatsby": {
        "category": "js_framework",
        "body": [r"___gatsby", r"/gatsby-"],
    },
    "Remix": {
        "category": "js_framework",
        "body": [r"__remixContext", r"@remix-run"],
    },

    # ── Analytics ─────────────────────────────────────────────────────────────
    "Google Analytics": {
        "category": "analytics",
        "body": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d{4,}-\d", r"G-[A-Z0-9]{6,}"],
    },
    "Google Tag Manager": {
        "category": "analytics",
        "body": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]{4,}"],
    },
    "Facebook Pixel": {
        "category": "analytics",
        "body": [r"connect\.facebook\.net/.+/fbevents\.js", r"fbq\("],
    },
    "Hotjar": {
        "category": "analytics",
        "body": [r"static\.hotjar\.com", r"hjid\s*:"],
    },
    "Mixpanel": {
        "category": "analytics",
        "body": [r"cdn\.mxpnl\.com", r"mixpanel\.init\("],
    },
    "HubSpot Analytics": {
        "category": "analytics",
        "body": [r"js\.hs-analytics\.net", r"js\.hsforms\.net"],
    },
    "Segment": {
        "category": "analytics",
        "body": [r"cdn\.segment\.com", r"analytics\.load\("],
    },
    "Plausible": {
        "category": "analytics",
        "body": [r"plausible\.io/js/plausible"],
    },
    "Matomo": {
        "category": "analytics",
        "body": [r"matomo\.js", r"piwik\.js"],
    },

    # ── WAF / Security ────────────────────────────────────────────────────────
    "Cloudflare WAF": {
        "category": "waf",
        "headers": {"cf-ray": r"."},
    },
    "AWS WAF": {
        "category": "waf",
        "headers": {"x-amzn-requestid": r".", "x-amzn-trace-id": r"."},
    },
    "Sucuri": {
        "category": "waf",
        "headers": {"x-sucuri-id": r".", "server": r"Sucuri"},
    },
    "Imperva": {
        "category": "waf",
        "headers": {"x-iinfo": r"."},
        "cookies": {"incap_ses": r".", "visid_incap": r"."},
    },
    "Barracuda": {
        "category": "waf",
        "cookies": {"barra_counter_session": r"."},
    },

    # ── Hosting / Infrastructure ──────────────────────────────────────────────
    "Vercel": {
        "category": "hosting",
        "headers": {"x-vercel-id": r".", "server": r"Vercel"},
    },
    "Netlify": {
        "category": "hosting",
        "headers": {"x-netlify": r".", "server": r"Netlify", "x-nf-request-id": r"."},
    },
    "GitHub Pages": {
        "category": "hosting",
        "headers": {"x-github-request-id": r"."},
    },
    "Heroku": {
        "category": "hosting",
        "headers": {"x-heroku-queue-wait-time": r"."},
        "cookies": {"heroku-session-affinity": r"."},
    },
    "AWS": {
        "category": "hosting",
        "headers": {"x-amz-request-id": r".", "x-amz-id-2": r"."},
    },
    "Google Cloud": {
        "category": "hosting",
        "headers": {"server": r"Google Frontend"},
    },
    "Render": {
        "category": "hosting",
        "headers": {"x-render-origin-server": r"."},
    },
    "Fly.io": {
        "category": "hosting",
        "headers": {"fly-request-id": r"."},
    },
}

# Human-readable category labels
CATEGORY_LABELS: dict = {
    "cdn":          "CDN",
    "web_server":   "Web Server",
    "cms":          "CMS / Platform",
    "language":     "Language / Runtime",
    "js_framework": "JS Framework",
    "analytics":    "Analytics",
    "waf":          "WAF / Security",
    "hosting":      "Hosting",
}


# ── Detection engine ──────────────────────────────────────────────────────────

def _match(sig: dict, headers: dict, body: str, cookies: dict) -> bool:
    for h_name, pattern in sig.get("headers", {}).items():
        if re.search(pattern, headers.get(h_name, ""), re.IGNORECASE):
            return True
    for pattern in sig.get("body", []):
        if re.search(pattern, body, re.IGNORECASE):
            return True
    for c_name, pattern in sig.get("cookies", {}).items():
        if re.search(pattern, cookies.get(c_name, ""), re.IGNORECASE):
            return True
    return False


def _analyse(headers: dict, body: str, cookies: dict) -> dict:
    detected: dict = {}
    for tech, sig in _SIGS.items():
        if _match(sig, headers, body, cookies):
            cat = sig["category"]
            detected.setdefault(cat, []).append(tech)
    return detected


# ── Public entry point ────────────────────────────────────────────────────────

def fetch_tech_stack(domain: str) -> dict:
    """
    Fetch the domain's home page and analyse headers + HTML body for
    technology fingerprints. Returns dict keyed by category.
    """
    headers: dict = {}
    body: str = ""
    cookies: dict = {}

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}",
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; OSINT-Aggregator/1.0)"},
            )
            headers  = {k.lower(): v for k, v in resp.headers.items()}
            body     = resp.content[:80_000].decode("utf-8", errors="ignore")
            cookies  = {k: v for k, v in resp.cookies.items()}
            break
        except Exception:
            continue

    if not headers and not body:
        return {"error": "Could not fetch page for tech analysis"}

    return _analyse(headers, body, cookies)
