"""Command-line entry point.

    python -m crucible.cli data/zap/juiceshop/juiceshop_zap_full.json \\
        --target http://juiceshop:3000 --backend docker

Reads a ZAP report, validates each finding in an ephemeral sandbox, prints a
scorecard, and writes a JSON report plus an append-only SQLite run log.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .agent import RefineAgent
from .ingest import ZapAdapter
from .normalize import normalize
from .report import scorecard_md, write_json
from .sandbox import make_sandbox
from .store import RunLog
from .validator import Validator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-10s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cli")


def _repo_root() -> Path:
    """src/crucible/cli.py -> repository root."""
    return Path(__file__).resolve().parents[2]


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no dependency). Existing env vars win."""
    candidates = [Path(path), _repo_root() / ".env"]
    seen: set[Path] = set()
    for p in candidates:
        p = p.resolve()
        if p in seen or not p.exists():
            continue
        seen.add(p)
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val and key not in os.environ:
                os.environ[key] = val


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="crucible",
        description="Validate scanner findings by re-exploiting them in an ephemeral sandbox.",
    )
    ap.add_argument("report", help="scanner report to validate (ZAP JSON)")
    ap.add_argument("--target", default="http://juiceshop:3000",
                    help="target base URL the scanner tested (its host filters findings)")
    ap.add_argument("--backend", choices=["docker", "local"], default="docker",
                    help="where to run steps: hardened container (docker) or host subprocess (local)")
    ap.add_argument("--sandbox-base", default=None,
                    help="base URL the sandbox uses to reach the target "
                         "(default docker=http://juiceshop:3000, local=http://localhost:3000)")
    ap.add_argument("--max-per-class", type=int, default=8,
                    help="cap instances validated per class so one noisy rule can't dominate")
    ap.add_argument("--max-attempts", type=int, default=3,
                    help="per-finding budget: 1 deterministic run + up to N-1 LLM refines")
    ap.add_argument("--out", default="data/output/juiceshop/validation_report.json",
                    help="JSON report path")
    ap.add_argument("--db", default="data/output/juiceshop/runs.db",
                    help="SQLite run-log path")
    ap.add_argument("--trace-out", default="data/output/juiceshop/llm_trace.jsonl",
                    help="per-iteration LLM/oracle trace (JSONL)")
    return ap


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)
    load_dotenv()   # pick up GEMINI_API_KEY / GEMINI_MODEL from ./.env if present

    raw = json.loads(open(args.report).read())
    findings = normalize(ZapAdapter().parse(raw, args.target),
                         max_per_class=args.max_per_class)
    log.info("parsed %d findings to validate", len(findings))
    if not findings:
        log.warning("no findings for host in %s -- check --target", args.target)
        return 1

    sandbox = make_sandbox(args.backend, args.sandbox_base)
    log.info("sandbox backend=%s target=%s", sandbox.backend, sandbox.target_base)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    Path(args.trace_out).parent.mkdir(parents=True, exist_ok=True)

    runlog = RunLog(args.db)
    runlog.start(target=sandbox.target_base, source="zap")
    validator = Validator(sandbox, agent=RefineAgent(), max_attempts=args.max_attempts)

    verdicts = []
    for finding in findings:
        v = validator.validate(finding)
        runlog.record(v)
        verdicts.append(v)
        log.info("%-14s %-16s %s", v.verdict.value, v.vuln_class.value, v.name)
    runlog.close()

    write_json(verdicts, sandbox.target_base, args.out)
    _write_trace(verdicts, args.trace_out)
    print("\n" + scorecard_md(verdicts, sandbox.target_base))
    print(f"\nJSON report -> {args.out}\nrun log     -> {args.db}\nLLM trace   -> {args.trace_out}")
    return 0


def _write_trace(verdicts, path: str) -> None:
    """One JSON line per iteration across all findings, for eyeballing the LLM."""
    with open(path, "w") as f:
        for v in verdicts:
            for entry in v.trace:
                line = {"finding_id": v.finding_id, "name": v.name,
                        "final_verdict": v.verdict.value, **entry}
                f.write(json.dumps(line) + "\n")


if __name__ == "__main__":
    sys.exit(main())
