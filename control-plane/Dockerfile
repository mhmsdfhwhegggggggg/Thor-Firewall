# Thor Firewall — Control Plane Dockerfile
# Multi-stage: builder → slim production image

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build
RUN pip install --upgrade pip uv

COPY control-plane/requirements.txt .
RUN uv pip install --system -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd -r thor && useradd -r -g thor -s /sbin/nologin thor

WORKDIR /app

# Copy installed packages
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source
COPY control-plane/src ./src
COPY control-plane/requirements.txt .

# WeasyPrint needs these fonts for PDF generation
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation libpango-1.0-0 libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Security hardening
RUN chmod -R 550 /app && chown -R thor:thor /app
USER thor

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"

CMD ["python3", "-m", "src.main"]
