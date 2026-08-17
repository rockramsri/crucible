"""The data model for the whole pipeline.

Everything is a small Pydantic model so it is easy to serialize (into the
sandbox, into the SQLite log, into the JSON report) and easy to read.

Flow of the models:

    Finding      -> what the scanner told us (one instance = one Finding)
    AttackPlan   -> Finding compiled by a playbook into concrete Steps
    Step         -> one HTTP request we will send
    StepResult   -> what came back (produced inside the sandbox)
    Verdict      -> the oracle's decision about the Finding
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class VulnClass(str, Enum):
    """The vulnerability classes we know how to validate.

    A Finding is mapped to one of these at ingestion time. UNKNOWN means we have
    no playbook for it yet, so the validator will skip it (but still count it).
    """

    SQLI = "sqli"
    XSS = "xss"
    OPEN_REDIRECT = "open_redirect"
    FILE_DISCLOSURE = "file_disclosure"
    ACL_BYPASS = "acl_bypass"
    CORS = "cors"
    UNKNOWN = "unknown"


class Target(BaseModel):
    """Where a finding lives: the absolute URL, HTTP method, and injected param."""

    uri: str
    method: str = "GET"
    param: str | None = None


class Finding(BaseModel):
    """One normalized finding from a scanner report (source-agnostic)."""

    id: str
    source: str = "zap"
    vuln_class: VulnClass
    name: str
    cwe: int | None = None
    severity: str = "Medium"          # High / Medium / Low / Informational
    scanner_confidence: str = "Medium"
    target: Target
    signal: dict = Field(default_factory=dict)   # {"attack": ..., "evidence": ...}
    raw: dict = Field(default_factory=dict)       # original alert, for traceability


class Step(BaseModel):
    """One HTTP request to send inside the sandbox.

    `json_body` is sent as a JSON request body; `params` become query params.
    We avoid the name `json` because it clashes with Pydantic's own method.
    """

    id: str
    method: str = "GET"
    path: str                                     # e.g. "/rest/user/login" (+ optional query)
    params: dict | None = None
    json_body: dict | None = None
    headers: dict | None = None
    follow_redirects: bool = True                 # set False to inspect 3xx (redirect / ACL tests)
    note: str | None = None                       # human hint, e.g. "baseline" / "attack"


class StepResult(BaseModel):
    """What the sandbox observed for a Step. No judgement here, just facts."""

    id: str
    status: int | None = None
    headers: dict = Field(default_factory=dict)
    body: str = ""                                # truncated response body
    body_len: int = 0
    elapsed_ms: int = 0
    error: str | None = None


class RunResult(BaseModel):
    """Everything the sandbox observed for one AttackPlan run."""

    finding_id: str
    results: list[StepResult] = Field(default_factory=list)

    def by_id(self) -> dict[str, StepResult]:
        """Results keyed by step id, which is how oracles look them up."""
        return {r.id: r for r in self.results}


class AttackPlan(BaseModel):
    """A Finding compiled into an ordered list of Steps plus a hypothesis.

    This is the exact object serialized to JSON and fed into the sandbox.
    """

    finding_id: str
    vuln_class: VulnClass
    target_base: str                              # e.g. "http://juiceshop:3000"
    hypothesis: str
    steps: list[Step]


class VerdictType(str, Enum):
    """The four honest outcomes, plus SKIPPED for classes we have no playbook for.

    Only CONFIRMED and FALSE_POSITIVE count toward the false-positive rate.
    AGENT_FAILURE (our bug) and INCONCLUSIVE (ran out of budget) are excluded so
    the headline number stays honest.
    """

    CONFIRMED = "confirmed"           # true positive, proven by the oracle
    FALSE_POSITIVE = "false_positive"  # target behaved safely / scanner artifact
    AGENT_FAILURE = "agent_failure"    # our request/tooling broke, not the target
    INCONCLUSIVE = "inconclusive"      # budget exhausted / needs a human
    SKIPPED = "skipped"                # no playbook for this class


class Verdict(BaseModel):
    """The oracle's decision about a Finding, with proof artifacts."""

    finding_id: str
    vuln_class: VulnClass
    name: str = ""
    verdict: VerdictType
    reason: str = ""
    proof: list[dict] = Field(default_factory=list)   # request/response artifacts
    attempts: int = 1
    elapsed_s: float = 0.0
    trace: list[dict] = Field(default_factory=list)   # per-iteration log (incl. LLM reasoning)
