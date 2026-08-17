"""Shared building blocks for playbooks.

A "playbook" is a small module per vulnerability class that knows two things:

    build_steps(finding, target_base) -> list[Step]     # how to re-test it
    oracle(finding, results)          -> OracleOutcome   # did it actually work

The oracle is pure, deterministic Python -- it is the only thing allowed to say
"this is real". Helpers below keep each playbook short and readable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from ..models import Finding, Step, StepResult, VerdictType

# Sentinels we look for when re-testing. Unlikely to appear by accident.
OOB_HOST = "oob-validator.example"      # open-redirect marker host
EVIL_ORIGIN = "https://evil-cors.example"  # CORS reflection probe
XSS_MARKER = "zapvalxss"                 # unique XSS reflection marker
SQLI_MARKER = "sqlivalmark7"             # unique value we UNION-inject to prove SQLi


@dataclass
class OracleOutcome:
    """Result of an oracle check.

    `verdict is None` means "not resolved yet" -- the loop may refine (LLM or a
    payload variant) if budget remains. A concrete verdict is final.

    `proof_steps` lists the step ids that constitute the evidence; the validator
    turns those into full request/response artifacts (it holds both the steps and
    their results), so oracles stay tiny and never fabricate requests.
    """

    verdict: VerdictType | None
    reason: str
    proof_steps: list[str] = field(default_factory=list)


# --- request helpers -------------------------------------------------------

def split_path_params(uri: str) -> tuple[str, dict]:
    """Split an absolute/relative URL into (path, query-params dict)."""
    parts = urlsplit(uri)
    path = parts.path or "/"
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    return path, params


# --- response helpers ------------------------------------------------------

def header(res: StepResult, name: str) -> str:
    """Case-insensitive header lookup (verify.py lower-cases header keys)."""
    return str(res.headers.get(name.lower(), ""))


def body_json(res: StepResult):
    """Best-effort parse of a response body as JSON, else None."""
    try:
        return json.loads(res.body)
    except Exception:
        return None


def token_from(res: StepResult):
    """Pull Juice Shop's auth token out of a login response, if present."""
    data = body_json(res)
    if isinstance(data, dict):
        auth = data.get("authentication")
        if isinstance(auth, dict):
            return auth.get("token")
    return None


def artifact(step: Step, res: StepResult) -> dict:
    """A compact request/response record to attach as proof."""
    return {
        "step": step.id,
        "request": {
            "method": step.method,
            "path": step.path,
            "params": step.params,
            "json": step.json_body,
            "headers": step.headers,
        },
        "response": {
            "status": res.status,
            "location": res.headers.get("location"),
            "body_snippet": res.body[:400],
        },
    }
