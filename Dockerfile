# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# ── OS-level dependencies for WeasyPrint ──────────────────────────────────────
# WeasyPrint is a Python wrapper around the Cairo/Pango/GDK-PixBuf C stack.
# These must be present at runtime — pip alone cannot install them.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Pango: text layout and font rendering
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    # Cairo: 2D graphics (PDF surface)
    libcairo2 \
    # GDK-PixBuf: image decoding (PNG/JPEG in reports)
    libgdk-pixbuf-2.0-0 \
    # libffi: required by cffi which WeasyPrint depends on
    libffi8 \
    # MIME database (WeasyPrint uses it for content-type sniffing)
    shared-mime-info \
    # Fonts — Liberation is a metrically-compatible MS fonts replacement
    fonts-liberation \
    fontconfig \
    && fc-cache -fv \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
WORKDIR /app

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────────────────────
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# ── Runtime ───────────────────────────────────────────────────────────────────
WORKDIR /app/backend

EXPOSE 8000

# Bind to 0.0.0.0 so the container port is reachable from outside
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
