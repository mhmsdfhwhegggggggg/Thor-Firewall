# Thor Firewall — Control Plane Dockerfile
FROM python:3.12-slim as base

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

RUN useradd -u 1000 -m thor && chown -R thor:thor /app
USER thor

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
