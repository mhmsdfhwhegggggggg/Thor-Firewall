# Thor Firewall — ML Inference Server Dockerfile
FROM nvidia/cuda:12.4-runtime-ubuntu22.04 AS gpu-runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ml/requirements-serve.txt ./requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY ml/serving/ ./serving/
COPY ml/ueba/    ./ueba/
COPY ml/online/  ./online/

# Model directory (mount as PV in K8s)
RUN mkdir -p /models && chmod 777 /models

RUN useradd -r -s /sbin/nologin thor && chown -R thor:thor /app
USER thor

EXPOSE 8080
HEALTHCHECK --interval=30s CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python3", "-m", "uvicorn", "serving.inference_server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
