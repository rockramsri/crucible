# Crucible console

React (TanStack Start) UI for **live validation lineage**. This folder is `ui/`
in the Crucible repo — not a separate GitHub project.

## Run locally

From the Crucible repo root:

```bash
# 1) backend — Server-Sent Events on :8000
pip install -e ".[api]"
./scripts/serve_api.sh

# 2) UI — Vite on :8080
cd ui
cp .env.example .env          # VITE_API_BASE=http://localhost:8000
npm install && npm run dev
```

- **Mock (default):** leave `VITE_API_BASE` unset/blank. The bundled Juice Shop
  sample replays entirely in the browser.
- **Live API:** set `VITE_API_BASE=http://localhost:8000`. The console POSTs a
  report to `/runs` and streams Server-Sent Events from `/runs/:id/stream`.

See the [root README](../README.md) for architecture, safety, and the validator CLI.
