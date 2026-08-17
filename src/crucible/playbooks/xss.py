"""Reflected XSS playbook (static reflection check).

We inject a unique marker with HTML-significant characters and confirm it comes
back UNescaped in an HTML response. Encoded reflection or no reflection is a
false positive. DOM-only XSS needs a real browser to prove and is out of scope
here -- it will honestly land as false_positive / inconclusive.
"""

from __future__ import annotations

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from .base import XSS_MARKER, OracleOutcome, split_path_params

VULN_CLASS = VulnClass.XSS

DOMAIN_BRIEF = """\
class: XSS (reflected)
success_effect: our unique payload is reflected UNescaped in an HTML response
                (the exact breakout string comes back, not an encoded version).
escalate_on_fail:
  - not reflected -> try a different parameter, or a context-specific breakout
    (attribute vs tag vs JS string); vary quotes/event handlers.
  - encoded       -> that is a FALSE POSITIVE (safely neutralized), not unresolved.
give_up_when: budget exhausted -> INCONCLUSIVE (DOM-only XSS needs a browser).
"""

# Breaks out of an attribute or tag; the marker makes accidental matches unlikely.
_PAYLOAD = f'"><svg/onload=alert({XSS_MARKER})>'


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    path, params = split_path_params(finding.target.uri)
    p = finding.target.param or (next(iter(params), None) or "q")
    merged = dict(params)
    merged[p] = _PAYLOAD
    return [
        Step(id="inject", method=(finding.target.method or "GET"), path=path,
             params=merged, follow_redirects=False, note="inject a unique breakout marker"),
    ]


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    res = results.get("inject")
    if not res:
        return OracleOutcome(VerdictType.AGENT_FAILURE, "inject step did not run")

    body = res.body or ""
    is_html = "html" in str(res.headers.get("content-type", "")).lower()

    if _PAYLOAD in body and is_html:
        return OracleOutcome(VerdictType.CONFIRMED,
                             "payload reflected unescaped in an HTML response", ["inject"])
    if XSS_MARKER in body:
        return OracleOutcome(VerdictType.FALSE_POSITIVE,
                             "marker reflected but encoded/neutralized; not executable")
    # Not reflected at all -> a different vector or parameter might work: let the LLM try.
    return OracleOutcome(None, "payload not reflected; may need a different vector or parameter")
