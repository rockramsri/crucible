"""403-bypass playbook.

The scanner claims a path trick (e.g. /%2e/ftp/secret.bak) sneaks past an
access control. We prove it: the direct path must be forbidden (403/401) while
the trick variant returns real content (200).
"""

from __future__ import annotations

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from ..util import looks_like_spa, path_with_query
from .base import OracleOutcome

VULN_CLASS = VulnClass.ACL_BYPASS

# Leading segments ZAP commonly uses to slip past a 403.
_TRICKS = ("/%2e", "/.", "/%2e%2e", "/..")


def _direct_path(bypass_path: str) -> str:
    """Strip a leading bypass segment to recover the genuinely-protected path."""
    for trick in _TRICKS:
        if bypass_path.startswith(trick + "/"):
            return bypass_path[len(trick):]
    return bypass_path


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    bypass = path_with_query(finding.target.uri)
    direct = _direct_path(bypass)
    return [
        Step(id="direct", method="GET", path=direct, follow_redirects=False,
             note="direct request to the protected path (expect 403/401)"),
        Step(id="bypass", method="GET", path=bypass, follow_redirects=False,
             note="path-trick variant (expect 200 if the bypass works)"),
    ]


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    direct, bypass = results.get("direct"), results.get("bypass")
    if not (direct and bypass):
        return OracleOutcome(VerdictType.AGENT_FAILURE, "direct/bypass steps did not both run")

    protected = direct.status in (401, 403)
    got_content = (bypass.status == 200 and bypass.body_len > 0
                   and not looks_like_spa(bypass.status, bypass.headers, bypass.body))

    if protected and got_content:
        return OracleOutcome(VerdictType.CONFIRMED,
                             f"403 bypass: direct={direct.status}, bypass=200 ({bypass.body_len} bytes)",
                             ["direct", "bypass"])
    if not protected:
        return OracleOutcome(VerdictType.FALSE_POSITIVE,
                             f"path is not actually protected (direct={direct.status}); nothing to bypass")
    return OracleOutcome(VerdictType.FALSE_POSITIVE,
                         f"bypass did not return content (bypass={bypass.status})")
