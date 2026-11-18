# Tamiz: one small image, no build step for the interface (plain HTML/CSS/JS).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TAMIZ_DATA_DIR=/data \
    TAMIZ_KEYS_DIR=/keys

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tamiz ./tamiz

# Runs as an unprivileged user. Files mounted into /keys must be readable by
# uid 10001 (chown 10001 keys/*), and /data must be writable by it.
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin tamiz \
 && mkdir -p /data /keys /waf \
 && chown tamiz /data
USER tamiz

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3).status == 200 else 1)"

# --no-proxy-headers: Tamiz reads X-Forwarded-* itself, and only from the
# addresses in TAMIZ_TRUSTED_PROXIES (see .env.example).
CMD ["uvicorn", "tamiz.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-proxy-headers"]
