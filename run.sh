#!/usr/bin/env bash
# One-command start: creates the venv, builds the UI if needed, runs the server on http://127.0.0.1:8000
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3.11}
if [ ! -d .venv ]; then "$PY" -m venv .venv; fi
.venv/bin/pip install -q -r requirements.txt
if [ ! -d frontend/out ] || [ "$1" == "--rebuild" ]; then
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi
[ -f .env ] || cp .env.example .env
HOST=$(grep -E '^HOST=' .env | cut -d= -f2); PORT=$(grep -E '^PORT=' .env | cut -d= -f2)
exec .venv/bin/uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
