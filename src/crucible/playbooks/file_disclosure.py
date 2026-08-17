"""Backup / source file disclosure playbook.

The scanner only guesses that a path *might* expose a file. We fetch it and
confirm it actually returns real bytes: HTTP 200, non-empty, and not just the
single-page-app shell Juice Shop serves for unknown paths.
"""

from __future__ import annotations

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from ..util import looks_like_spa, path_with_query
from .base import OracleOutcome

VULN_CLASS = VulnClass.FILE_DISCLOSURE


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    return [
        Step(id="fetch", method="GET", path=path_with_query(finding.target.uri),
             follow_redirects=False, note="fetch the allegedly-exposed file"),
    ]


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    res = results.get("fetch")
    if not res:
        return OracleOutcome(VerdictType.AGENT_FAILURE, "fetch step did not run")
    if res.error:
        return OracleOutcome(VerdictType.AGENT_FAILURE, f"request error: {res.error}")

    spa = looks_like_spa(res.status, res.headers, res.body)
    if res.status == 200 and res.body_len > 0 and not spa:
        return OracleOutcome(VerdictType.CONFIRMED,
                             f"file is served: HTTP 200, {res.body_len} bytes",
                             ["fetch"])
    return OracleOutcome(VerdictType.FALSE_POSITIVE,
                         f"not a real disclosure (status={res.status}, spa_shell={spa})")
