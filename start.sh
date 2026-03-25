#!/usr/bin/env bash
set -euo pipefail

if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -r requirements.txt

PORT="${PORT:-8000}"

echo "Starting ReconScan local dev server at http://localhost:${PORT} ..."
echo "USE_ARQ_QUEUE is forced to false for local dev convenience."
echo "If this port is busy, rerun with PORT=<your_port> ./start.sh"
USE_ARQ_QUEUE=false uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --reload
