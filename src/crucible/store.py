"""Append-only SQLite run log -- a small, reproducible audit trail.

One row per verdict, plus a run header. Append-only: we never update or delete,
so the log is a faithful history of what the validator did on each run.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from .models import Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id     TEXT PRIMARY KEY,
    started_at TEXT,
    target     TEXT,
    source     TEXT
);
CREATE TABLE IF NOT EXISTS verdicts (
    run_id     TEXT,
    finding_id TEXT,
    vuln_class TEXT,
    name       TEXT,
    verdict    TEXT,
    reason     TEXT,
    attempts   INTEGER,
    elapsed_s  REAL,
    proof      TEXT,
    trace      TEXT,
    logged_at  TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunLog:
    def __init__(self, path: str = "runs.db"):
        self.path = path
        self.run_id = uuid.uuid4().hex[:12]
        self._conn = sqlite3.connect(path)
        self._conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add columns that older run-logs may be missing (idempotent)."""
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(verdicts)")}
        if "trace" not in cols:
            self._conn.execute("ALTER TABLE verdicts ADD COLUMN trace TEXT")
            self._conn.commit()

    def start(self, target: str, source: str) -> None:
        self._conn.execute(
            "INSERT INTO runs(run_id, started_at, target, source) VALUES (?,?,?,?)",
            (self.run_id, _now(), target, source),
        )
        self._conn.commit()

    def record(self, v: Verdict) -> None:
        self._conn.execute(
            "INSERT INTO verdicts(run_id, finding_id, vuln_class, name, verdict, reason,"
            " attempts, elapsed_s, proof, trace, logged_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (self.run_id, v.finding_id, v.vuln_class.value, v.name, v.verdict.value,
             v.reason, v.attempts, v.elapsed_s, json.dumps(v.proof), json.dumps(v.trace), _now()),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
