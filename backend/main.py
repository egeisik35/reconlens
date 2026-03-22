from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import Response
from pydantic import BaseModel, field_validator
import re
import os

from osint import run_all
from pdf_gen import generate_pdf

app = FastAPI(title="OSINT Aggregator")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


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
    headers: dict = {}
    errors: dict = {}


@app.post("/api/lookup")
async def lookup(req: LookupRequest):
    try:
        result = run_all(req.domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/export-pdf")
async def export_pdf(req: ExportRequest):
    try:
        pdf_bytes = generate_pdf(req.model_dump())
        filename = f"osint-report-{req.domain}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Serve the frontend
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
