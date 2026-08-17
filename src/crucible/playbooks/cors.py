"""CORS misconfiguration playbook.

Send a request with an attacker-controlled Origin and see whether the app
trusts it. The exploitable case is reflecting an arbitrary Origin back in
Access-Control-Allow-Origin (optionally with credentials allowed).
"""

from __future__ import annotations

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from ..util import path_with_query
from .base import EVIL_ORIGIN, OracleOutcome, header

VULN_CLASS = VulnClass.CORS


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    return [
        Step(id="probe", method=(finding.target.method or "GET"),
             path=path_with_query(finding.target.uri),
             headers={"Origin": EVIL_ORIGIN},
             follow_redirects=False,
             note="request with an attacker-controlled Origin"),
    ]


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    res = results.get("probe")
    if not res:
        return OracleOutcome(VerdictType.AGENT_FAILURE, "probe step did not run")

    acao = header(res, "access-control-allow-origin")
    with_creds = header(res, "access-control-allow-credentials").lower() == "true"

    if acao == EVIL_ORIGIN:
        detail = "with credentials (exploitable)" if with_creds else "without credentials"
        return OracleOutcome(VerdictType.CONFIRMED,
                             f"reflects an arbitrary Origin {detail}", ["probe"])
    return OracleOutcome(VerdictType.FALSE_POSITIVE,
                         f"origin not reflected (ACAO={acao or 'none'}); not exploitable this way")
