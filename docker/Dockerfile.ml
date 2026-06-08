# Thor Firewall — ML Serving Container
FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Thor Firewall ML Serving"
LABEL org.opencontainers.image.description="MARL/GNN/LLM inference server"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# ===== Dependencies =====
FROM base AS deps

WORKDIR /app

COPY ml/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

# ===== Runtime =====
FROM base AS runtime

WORKDIR /app

COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# إنشاء مستخدم غير مميز
RUN groupadd -r thor && useradd -r -g thor thor

COPY ml/ ./ml/
COPY configs/ ./configs/

# إنشاء مجلدات البيانات
RUN mkdir -p models checkpoints data && chown -R thor:thor /app

USER thor

EXPOSE 8001 9092

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["python", "-m", "ml.serving.inference_server"]
