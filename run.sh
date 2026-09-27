#!/usr/bin/env bash
# One-command start: creates the venv, builds the UI if needed, runs the server (HOST / PORT from .env).
#   ./run.sh              real data (data/edr_assets.db)
#   ./run.sh --rebuild    rebuild the web UI first
#   ./run.sh --demo       sample data in data/demo.db (the real database is not touched, syncing is off)
set -e
cd "$(dirname "$0")"
REBUILD=0
for a in "$@"; do
  case "$a" in
    --rebuild) REBUILD=1 ;;
    --demo) export DEMO=1 ;;
  esac
done
PY=${PYTHON:-python3.11}
if [ ! -d .venv ]; then "$PY" -m venv .venv; fi
.venv/bin/pip install -q -r requirements.txt
if [ ! -d frontend/out ] || [ "$REBUILD" == "1" ]; then
  (cd frontend && npm install --no-audit --no-fund && npm run build)
fi
[ -f .env ] || cp .env.example .env
HOST=$(grep -E '^HOST=' .env | cut -d= -f2); PORT=$(grep -E '^PORT=' .env | cut -d= -f2)
[ -n "$DEMO" ] && echo "Sample data mode: data/demo.db (your real database is not used)"
exec .venv/bin/uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
