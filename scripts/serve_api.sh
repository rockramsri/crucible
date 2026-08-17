#!/usr/bin/env bash
#
# Start the Crucible live API (FastAPI + SSE) that the Ops Layer UI talks to.
#
#   pip install -e ".[api]"      # once
#   ./scripts/serve_api.sh        # http://localhost:8000
#
# The UI connects when its VITE_API_BASE points here (see the UI's .env.example).
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec "${PYTHON:-python}" -m crucible.api --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" ${RELOAD:+--reload}
