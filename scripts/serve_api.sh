#!/usr/bin/env bash
#
# Start the Crucible live API (FastAPI + SSE) that the console (ui/) talks to.
#
#   pip install -e ".[api]"      # once (prefer: .venv/bin/pip install -e ".[api]")
#   ./scripts/serve_api.sh        # http://localhost:8000
#
# Prefers the project .venv so Anaconda `python` is not used by accident.
# The API loads repo-root `.env` at startup (OPENAI_API_KEY / ADAPTIVE_MODEL).
# Empty keys disable the adaptive layer: unresolved SQLi stays INCONCLUSIVE.
#
# The UI connects when its VITE_API_BASE points here (see the UI's .env.example).
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -n "${PYTHON:-}" ]; then
  PY="${PYTHON}"
elif [ -x "${ROOT}/.venv/bin/python" ]; then
  PY="${ROOT}/.venv/bin/python"
else
  PY="python"
fi

echo "crucible-api using: ${PY}" >&2
"${PY}" -c 'import sys; print("  executable:", sys.executable, file=sys.stderr)'

exec "${PY}" -m crucible.api --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" ${RELOAD:+--reload}
