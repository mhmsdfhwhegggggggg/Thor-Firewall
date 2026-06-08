# Thor Firewall — ML Service Dockerfile
FROM python:3.12-slim as base

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y \
    curl build-essential git \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Non-root user
RUN useradd -u 1000 -m thor && chown -R thor:thor /app
USER thor

EXPOSE 8082

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8082/health || exit 1

CMD ["python", "serving/inference_server.py"]
