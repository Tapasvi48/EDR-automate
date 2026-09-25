# syntax=docker/dockerfile:1

# ---- 1. build the Next.js UI (static export) ----
# static files are identical on every platform, so build them once on the native builder
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /ui
ENV NEXT_TELEMETRY_DISABLED=1
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 2. runtime: FastAPI + SQLite, serves the API and the built UI ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/edr_assets.db \
    HOST=0.0.0.0 \
    PORT=8765
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
COPY --from=ui /ui/out frontend/out
RUN useradd --system --uid 10001 edr && mkdir -p /data && chown edr:edr /data
USER edr
# database, API credentials and uploaded inventories live here - mount a volume to keep them
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/sync/status', timeout=4)" || exit 1
CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$HOST\" --port \"$PORT\" --proxy-headers"]
