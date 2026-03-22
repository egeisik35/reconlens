import json
import logging
import re
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response, HTMLResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from osint import run_all
from pdf_gen import generate_pdf
from database import init_db, get_conn
from monitor import take_snapshot
from mailer import send_confirmation
from scheduler import start_scheduler, stop_scheduler

logger = logging.getLogger(__name__)

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    start_scheduler()
    yield
    stop_scheduler()

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="ReconLens", lifespan=lifespan)
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
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Content-Type"],
)

# ── Helpers ────────────────────────────────────────────────────────────────────
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_EMAIL_RE       = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
_SAFE_FNAME_RE  = re.compile(r"[^a-z0-9\-\.]")

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


def _validate_domain(v: str) -> str:
    v = v.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not DOMAIN_RE.match(v):
        raise ValueError("Invalid domain name")
    return v


# ── Request models ─────────────────────────────────────────────────────────────
class LookupRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)


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
        return _validate_domain(v)


class WatchRequest(BaseModel):
    domain: str
    email: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
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
        pdf_bytes  = generate_pdf(req.model_dump())
        safe_name  = _SAFE_FNAME_RE.sub("-", req.domain)
        filename   = f"reconlens-report-{safe_name}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error("PDF export failed for %s: %s", req.domain, e, exc_info=True)
        raise HTTPException(status_code=500, detail="PDF generation failed. Please try again.")


@app.post("/api/watch")
@limiter.limit("3/minute")
async def watch(request: Request, req: WatchRequest):
    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM monitors WHERE domain=? AND email=?",
        (req.domain, req.email),
    ).fetchone()
    conn.close()

    if existing:
        return {"message": f"Already watching {req.domain} for {req.email}."}

    monitor_id = str(uuid.uuid4())
    now        = datetime.now(timezone.utc).isoformat()

    try:
        snapshot = take_snapshot(req.domain)
    except Exception as e:
        logger.error("Snapshot failed for %s: %s", req.domain, e, exc_info=True)
        raise HTTPException(status_code=500, detail="Could not snapshot domain. Please try again.")

    conn = get_conn()
    conn.execute(
        "INSERT INTO monitors (id, domain, email, created_at, last_checked, snapshot) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (monitor_id, req.domain, req.email, now, now, json.dumps(snapshot)),
    )
    conn.commit()
    conn.close()

    email_error = None
    try:
        send_confirmation(domain=req.domain, email=req.email, monitor_id=monitor_id)
    except Exception as e:
        logger.error("Confirmation email failed for %s: %s", req.email, e)
        email_error = str(e)

    response = {"message": f"Now watching {req.domain}. Alerts will be sent to {req.email}."}
    if email_error:
        response["warning"] = "Monitor saved, but confirmation email failed. Check RESEND_API_KEY."
    return response


@app.get("/api/unwatch")
async def unwatch(id: str):
    conn = get_conn()
    row = conn.execute(
        "SELECT domain, email FROM monitors WHERE id=?", (id,)
    ).fetchone()

    if not row:
        conn.close()
        return HTMLResponse(
            "<html><body style='font-family:monospace;padding:40px'>"
            "<h2>Not found</h2><p>This monitor doesn't exist or was already removed.</p>"
            "</body></html>",
            status_code=404,
        )

    domain, email = row["domain"], row["email"]
    conn.execute("DELETE FROM monitors WHERE id=?", (id,))
    conn.commit()
    conn.close()

    return HTMLResponse(f"""
        <html><head><title>Unsubscribed</title></head>
        <body style="font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;
                     display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
          <div style="text-align:center">
            <div style="color:#58a6ff;font-size:1.4rem;font-weight:700;margin-bottom:12px">
              ReconLens
            </div>
            <h2 style="color:#c9d1d9;margin-bottom:8px">Unsubscribed</h2>
            <p style="color:#8b949e">
              <strong style="color:#c9d1d9">{email}</strong> will no longer
              receive alerts for <strong style="color:#58a6ff">{domain}</strong>.
            </p>
            <a href="/" style="color:#58a6ff;font-size:0.85rem">Back to ReconLens</a>
          </div>
        </body></html>
    """)


# Serve the frontend — must be mounted last
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
