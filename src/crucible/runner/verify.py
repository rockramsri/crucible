"""Sandbox step executor -- the ONLY code that runs inside the container.

It reads an AttackPlan as JSON on stdin, sends each HTTP step at the target,
and writes the raw results as JSON on stdout. It makes NO decisions: no oracle,
no LLM, no verdict. That keeps the box dumb, auditable, and safe to lock down
(no secrets, no internet -- it only ever talks to the target it is handed).

    python verify.py  < plan.json  > result.json

plan.json (subset of AttackPlan):
    {
      "finding_id": "...",
      "target_base": "http://juiceshop:3000",
      "steps": [
        {"id","method","path","params","json_body","headers","follow_redirects"}
      ]
    }
"""

from __future__ import annotations

import json
import sys
import time

import httpx

BODY_CAP = 4000  # oracles only need a slice; keep snippets small


def run_step(client: httpx.Client, base: str, step: dict) -> dict:
    started = time.perf_counter()
    try:
        resp = client.request(
            step.get("method", "GET"),
            base.rstrip("/") + step["path"],
            params=step.get("params") or None,
            json=step.get("json_body") or None,
            headers=step.get("headers") or None,
            follow_redirects=bool(step.get("follow_redirects", True)),
            timeout=15.0,
        )
        body = resp.text or ""
        return {
            "id": step["id"],
            "status": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "body": body[:BODY_CAP],
            "body_len": len(body),
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "error": None,
        }
    except Exception as exc:  # a transport error is a fact to report, not a verdict
        return {
            "id": step["id"], "status": None, "headers": {}, "body": "",
            "body_len": 0, "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def main() -> None:
    plan = json.load(sys.stdin)
    base = plan["target_base"]
    results = []
    # One client for the whole plan so a later step can reuse cookies set earlier.
    with httpx.Client() as client:
        for step in plan.get("steps", []):
            results.append(run_step(client, base, step))
    json.dump({"finding_id": plan.get("finding_id"), "results": results}, sys.stdout)


if __name__ == "__main__":
    main()
