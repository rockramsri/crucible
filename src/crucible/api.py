"""Crucible HTTP API — the live backend the UI (Ops Layer) talks to.

Two ways to start a run (both stream the SAME Server-Sent-Events sequence the
front-end already understands, so mock and live drive identical UI code):

    POST /runs   { "report": <validation_report.json>, "speed"?: 1 }
        Replay an already-computed report as a live event stream. This is what
        the UI posts today (drag a report / "Run sample"). No Docker needed.

    POST /runs   { "zap": <raw ZAP JSON>, "target": "http://juiceshop:3000",
                   "backend"?: "docker"|"local", "max_attempts"?: 3,
                   "adaptive"?: true, "max_per_class"?: 8, "sandbox_base"?: null }
        Run the REAL validator against a live target and stream true results as
        each finding is decided. Needs a reachable target + Docker (or local).

Then subscribe:

    GET  /runs/{run_id}/stream        (text/event-stream, default `data:` frames)

Run it:  pip install -e ".[api]"  &&  crucible-api      (uvicorn on :8000)
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import Counter
from typing import Any, Awaitable, Callable

log = logging.getLogger("api")

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "The API needs FastAPI + uvicorn. Install them with:\n"
        '    pip install -e ".[api]"'
    ) from exc


# --------------------------------------------------------------------------- #
# Event stream shared by replay + live (mirrors the UI's CrucibleEvent union)
# --------------------------------------------------------------------------- #

Emit = Callable[[dict[str, Any]], Awaitable[None]]

# Fallback attack path per class, matching the UI's replay.ts pathFor().
_FALLBACK_PATH = {
    "sqli": "/rest/products/search",
    "xss": "/#/search",
    "open_redirect": "/redirect",
    "acl_bypass": "/ftp/quarantine",
    "cors": "/rest/user/whoami",
    "file_disclosure": "/ftp",
}


def _path_for(verdict: dict[str, Any]) -> str:
    proof = (verdict.get("proof") or [{}])[0]
    path = ((proof or {}).get("request") or {}).get("path")
    if path:
        return path
    return _FALLBACK_PATH.get(verdict.get("vuln_class", ""), "/")


def _summary(verdicts: list[dict[str, Any]], total: int) -> dict[str, Any]:
    c = Counter(v.get("verdict") for v in verdicts)
    confirmed, fp = c.get("confirmed", 0), c.get("false_positive", 0)
    denom = confirmed + fp
    return {
        "total": total,
        "confirmed": confirmed,
        "false_positive": fp,
        "inconclusive": c.get("inconclusive", 0),
        "agent_failure": c.get("agent_failure", 0),
        "skipped": c.get("skipped", 0),
        "false_positive_rate": (fp / denom) if denom else 0,
    }


async def _emit_finding(verdict: dict[str, Any], emit: Emit, wait) -> None:
    """Turn one Verdict (report shape) into the paced event sequence for a finding."""
    fid = verdict["finding_id"]
    await emit({
        "type": "finding.start",
        "finding_id": fid,
        "vuln_class": verdict["vuln_class"],
        "name": verdict.get("name", ""),
        "severity": verdict.get("severity"),
    })
    await wait(420)

    path = _path_for(verdict)
    for entry in verdict.get("trace", []):
        if entry.get("kind") == "diagnose":
            await wait(700)
            await emit({
                "type": "diagnose",
                "finding_id": fid,
                "attempt": entry.get("n", 1),
                "reasoning": entry.get("reasoning", ""),
                "hypotheses": entry.get("hypotheses", []),
                "giveup": entry.get("giveup", False),
            })
            await wait(800)
            continue

        # kind == "run"
        steps = entry.get("steps", [])
        observed = entry.get("observed", {})
        mode = entry.get("mode", "deterministic")
        step_delay = 60 if len(steps) > 12 else 320   # compress long adaptive sweeps
        for step in steps:
            sid = step["id"]
            await emit({
                "type": "step.sent",
                "finding_id": fid,
                "attempt": entry.get("n", 1),
                "step_id": sid,
                "method": "GET",
                "path": path,
                "payload": step.get("payload", ""),
                "mode": mode,
            })
            await wait(step_delay)
            obs = observed.get(sid, {"status": 0, "len": 0})
            await emit({
                "type": "step.result",
                "finding_id": fid,
                "attempt": entry.get("n", 1),
                "step_id": sid,
                "status": obs.get("status", 0),
                "body_len": obs.get("len", 0),
                "elapsed_ms": 40 + (len(sid) % 7) * 11,
            })
            await wait(step_delay * 0.75)

        if entry.get("verdict") == "unresolved":
            await emit({
                "type": "oracle.interim",
                "finding_id": fid,
                "attempt": entry.get("n", 1),
                "oracle": entry.get("oracle", ""),
                "verdict": "unresolved",
            })
            await wait(700)

    await wait(420)
    await emit({
        "type": "verdict",
        "finding_id": fid,
        "verdict": verdict["verdict"],
        "reason": verdict.get("reason", ""),
        "attempts": verdict.get("attempts", 1),
        "elapsed_s": verdict.get("elapsed_s", 0),
        "proof": verdict.get("proof", []),
    })
    await wait(520)


# --------------------------------------------------------------------------- #
# Producers
# --------------------------------------------------------------------------- #

async def _run_from_report(report: dict[str, Any], emit: Emit, wait, run_id: str) -> None:
    verdicts = report.get("verdicts", [])
    await emit({
        "type": "run.start",
        "run_id": run_id,
        "target": report.get("target", ""),
        "source": "zap",
        "total": len(verdicts),
    })
    for verdict in verdicts:
        await _emit_finding(verdict, emit, wait)
    await emit({
        "type": "run.done",
        "summary": report.get("summary") or _summary(verdicts, len(verdicts)),
    })


async def _run_live(body: dict[str, Any], emit: Emit, wait, run_id: str) -> None:
    """Run the real validator against a live target and stream results per finding."""
    from .agent import RefineAgent
    from .cli import load_dotenv
    from .ingest import ZapAdapter
    from .normalize import normalize
    from .sandbox import make_sandbox
    from .validator import Validator

    load_dotenv()
    target = body.get("target", "http://juiceshop:3000")
    raw = body["zap"]
    if isinstance(raw, str):
        raw = json.loads(raw)

    findings = normalize(
        ZapAdapter().parse(raw, target),
        max_per_class=int(body.get("max_per_class", 8)),
    )
    sandbox = make_sandbox(body.get("backend", "docker"), body.get("sandbox_base"))
    agent = RefineAgent() if body.get("adaptive", True) else None
    validator = Validator(sandbox, agent=agent, max_attempts=int(body.get("max_attempts", 3)))

    await emit({
        "type": "run.start",
        "run_id": run_id,
        "target": sandbox.target_base,
        "source": "zap",
        "total": len(findings),
    })

    loop = asyncio.get_running_loop()
    verdicts: list[dict[str, Any]] = []
    for finding in findings:
        # The validator is blocking (Docker/HTTP); run it off the event loop.
        verdict = await loop.run_in_executor(None, validator.validate, finding)
        vd = verdict.model_dump(mode="json")
        verdicts.append(vd)
        await _emit_finding(vd, emit, wait)

    await emit({"type": "run.done", "summary": _summary(verdicts, len(findings))})


# --------------------------------------------------------------------------- #
# App + run registry
# --------------------------------------------------------------------------- #

app = FastAPI(title="Crucible API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # demo: any origin (Lovable, localhost, Pages)
    allow_methods=["*"],
    allow_headers=["*"],
)

# run_id -> {"q": asyncio.Queue, "cancel": asyncio.Event, "task": Task}
_RUNS: dict[str, dict[str, Any]] = {}


@app.get("/")
def root() -> dict[str, Any]:
    return {"service": "crucible-api", "runs": len(_RUNS),
            "post": "/runs {report|zap}", "stream": "/runs/{id}/stream"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/runs")
async def create_run(request: Request) -> JSONResponse:
    body = await request.json()
    if "report" not in body and "zap" not in body:
        raise HTTPException(400, "body must include either 'report' or 'zap'")

    run_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    cancel = asyncio.Event()
    _RUNS[run_id] = {"q": queue, "cancel": cancel}

    speed = float(body.get("speed", 1) or 1)

    async def emit(event: dict[str, Any]) -> None:
        if not cancel.is_set():
            queue.put_nowait(event)

    async def wait(ms: float) -> None:
        # Cancel-aware pacing; keeps the stream trickling like the UI's replay.
        try:
            await asyncio.wait_for(cancel.wait(), timeout=max(0.004, ms / 1000 / speed))
        except asyncio.TimeoutError:
            pass

    async def producer() -> None:
        try:
            if "report" in body:
                await _run_from_report(body["report"], emit, wait, run_id)
            else:
                await _run_live(body, emit, wait, run_id)
        except Exception as exc:  # surface, don't hang the stream
            log.exception("run %s failed", run_id)
            await emit({"type": "run.error", "message": str(exc)})
        finally:
            queue.put_nowait(None)   # sentinel: closes the SSE stream

    _RUNS[run_id]["task"] = asyncio.create_task(producer())
    return JSONResponse({"run_id": run_id})


@app.get("/runs/{run_id}/stream")
async def stream_run(run_id: str) -> StreamingResponse:
    rec = _RUNS.get(run_id)
    if not rec:
        raise HTTPException(404, "unknown run_id")
    queue: asyncio.Queue = rec["q"]

    async def gen():
        try:
            yield ": crucible stream open\n\n"   # prelude so proxies flush early
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            rec["cancel"].set()
            _RUNS.pop(run_id, None)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",   # disable nginx buffering (Railway/proxies)
        },
    )


def main() -> None:
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser(prog="crucible-api", description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--reload", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)-8s %(levelname)-7s %(message)s")
    uvicorn.run("crucible.api:app" if args.reload else app,
                host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
