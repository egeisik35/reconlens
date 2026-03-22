import logging
import re
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from osint import run_all
from pdf_gen import generate_pdf

logger = logging.getLogger(__name__)

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="OSINT Aggregator")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Security headers middleware ────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

# ── Helpers ────────────────────────────────────────────────────────────────────
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

# Allowed characters for a safe Content-Disposition filename
_SAFE_FILENAME_RE = re.compile(r"[^a-z0-9\-\.]")

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


# ── Request models ─────────────────────────────────────────────────────────────
class LookupRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not DOMAIN_RE.match(v):
            raise ValueError("Invalid domain name")
        return v


class ExportRequest(BaseModel):
    domain: str
    dns: dict = {}
    whois: dict = {}
    ssl: dict = {}
    ip_reputation: list = []
    tech_stack: dict = {}
    headers: dict = {}
    ct: dict = {}
    errors: dict = {}

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
        if not DOMAIN_RE.match(v):
            raise ValueError("Invalid domain name")
        return v


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.post("/api/lookup")
@limiter.limit("10/minute")
async def lookup(request: Request, req: LookupRequest):
    try:
        result = run_all(req.domain)
        return result
    except Exception as e:
        logger.error("Lookup failed for %s: %s", req.domain, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Lookup failed. Please try again.")


@app.post("/api/export-pdf")
@limiter.limit("10/minute")
async def export_pdf(request: Request, req: ExportRequest):
    try:
        pdf_bytes = generate_pdf(req.model_dump())
        safe_domain = _SAFE_FILENAME_RE.sub("-", req.domain)
        filename = f"osint-report-{safe_domain}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error("PDF export failed for %s: %s", req.domain, e, exc_info=True)
        raise HTTPException(status_code=500, detail="PDF generation failed. Please try again.")


# Serve the frontend — must be mounted last
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
