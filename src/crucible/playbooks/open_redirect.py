"""Open / external redirect playbook.

Prove the app will 3xx a user to an attacker-controlled host. We send our own
marker host in the redirect parameter and also replay the scanner's original
payload (which already encoded any allow-list bypass), then check whether the
Location header actually points off-site.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from .base import OOB_HOST, OracleOutcome, header, split_path_params

VULN_CLASS = VulnClass.OPEN_REDIRECT

_COMMON_PARAMS = ("to", "url", "redirect", "returnUrl", "return", "next", "dest", "target")


def _redirect_param(finding: Finding, params: dict) -> str:
    """Which query parameter carries the redirect URL."""
    if finding.target.param:
        return finding.target.param
    for cand in _COMMON_PARAMS:
        if cand in params:
            return cand
    return next(iter(params), "to")


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    path, params = split_path_params(finding.target.uri)
    p = _redirect_param(finding, params)

    def variant(pid: str, value: str, note: str) -> Step:
        merged = dict(params)
        merged[p] = value
        return Step(id=pid, method="GET", path=path, params=merged,
                    follow_redirects=False, note=note)

    steps = [
        variant("baseline", "/account", "baseline: a safe same-site path"),
        variant("attack_marker", f"https://{OOB_HOST}/", "attack: bare off-site URL"),
    ]
    # Replay the scanner's exact payload -- it already encodes any allow-list
    # bypass the app requires (e.g. appending an allowed URL as a suffix).
    scanner_attack = (finding.signal or {}).get("attack")
    if scanner_attack:
        steps.append(variant("attack_scanner", scanner_attack, "attack: scanner's original payload"))
    return steps


def _location_host(res: StepResult) -> str:
    return urlsplit(header(res, "location")).netloc.lower()


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    target_host = urlsplit(finding.target.uri).netloc.lower()

    baseline = results.get("baseline")
    if baseline and _location_host(baseline) and _location_host(baseline) != target_host:
        # If even a safe value already redirects off-site, the endpoint proves nothing.
        return OracleOutcome(VerdictType.FALSE_POSITIVE,
                             "baseline already redirects off-site; not a controllable redirect")

    for pid in ("attack_marker", "attack_scanner"):
        res = results.get(pid)
        if not res or not res.status:
            continue
        loc_host = _location_host(res)
        if 300 <= res.status < 400 and loc_host and loc_host != target_host:
            # Our marker variant must land on OUR host; the scanner replay may go anywhere off-site.
            if pid == "attack_marker" and OOB_HOST not in loc_host:
                continue
            return OracleOutcome(VerdictType.CONFIRMED,
                                 f"open redirect via {pid}: Location -> {loc_host}",
                                 ["baseline", pid])

    return OracleOutcome(VerdictType.FALSE_POSITIVE,
                         "no off-site redirect produced; the parameter looks validated")
