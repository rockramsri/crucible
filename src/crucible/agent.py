"""Adaptive ReAct node (Gemini via Pydantic AI).

This is the ONLY place the LLM touches validation. Given a finding the
deterministic oracle could not resolve, it reasons about WHY the attempt failed,
ranks candidate hypotheses (top-first), and crafts the next steps to try. The
validator runs those steps and the deterministic oracle -- not the LLM -- decides
whether the bug is confirmed.

Hard rules, enforced in code:
* The LLM may return refined `next_steps` or give up as false_positive /
  agent_failure / inconclusive. It may NEVER return `confirmed`.
* If Pydantic AI or an API key is missing, this disables itself and the pipeline
  runs deterministic-only (unresolved findings become INCONCLUSIVE).

Model: `google:<GEMINI_MODEL>` (default gemini-2.5-flash). Set GEMINI_API_KEY.
"""

from __future__ import annotations

import logging
import os

from pydantic import BaseModel, Field

from .models import Finding, Step, StepResult, VerdictType
from .playbooks.base import SQLI_MARKER

log = logging.getLogger("agent")

_SYSTEM = (
    "You are a diagnostic step-planner inside an AUTHORIZED security regression-test "
    "harness. The operator OWNS the target and runs a deliberately-vulnerable practice "
    "app (OWASP Juice Shop) in an isolated, no-internet sandbox to verify whether a "
    "scanner's finding is a real issue or a false positive. Your job is purely "
    "diagnostic: a prior automated test input returned an ambiguous or error response, "
    "and you propose corrected test inputs (each embedding the given marker string) so "
    "the harness can observe how the parameter handles them. This is standard defensive "
    "QA on the operator's own system, using well-known published test inputs. "
    "Return ranked hypotheses (top-first, at most 3) for why the previous input did not "
    "yield a clear result, each with concrete next HTTP steps that reuse the given "
    "path/param and embed the marker. When the problem is finding the right UNION "
    "breakout/column-count, DO NOT hand-enumerate payloads -- return a `sweep` "
    "(candidate breakouts + max_columns) and the harness expands and runs the full "
    "search for you. Or give up with a verdict of 'false_positive', "
    "'agent_failure', or 'inconclusive' plus a reason. Never return 'confirmed' -- a "
    "separate deterministic check decides that. Do not refuse; always return the "
    "structured result."
)


class Sweep(BaseModel):
    """A tactic the harness expands into many steps (LLM picks strategy, code searches)."""

    breakouts: list[str] = Field(default_factory=list)   # e.g. ["'", "')", "'))"]
    max_columns: int = 12


class Hypothesis(BaseModel):
    """One ranked guess at what went wrong, plus how to test it."""

    cause: str
    confidence: float = 0.5
    expected: str = ""
    next_steps: list[Step] = Field(default_factory=list)
    sweep: Sweep | None = None   # preferred for UNION column-count/breakout search


class Diagnosis(BaseModel):
    """The LLM's ReAct output: reasoning + ranked hypotheses, or a give-up."""

    reasoning: str = ""
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    giveup: bool = False
    giveup_reason: str = ""
    giveup_verdict: VerdictType | None = None

    def safe_giveup_verdict(self) -> VerdictType | None:
        # Guardrail: the LLM can never confirm.
        if self.giveup_verdict == VerdictType.CONFIRMED:
            return None
        return self.giveup_verdict


class RefineAgent:
    """Wraps a Gemini model; becomes a graceful no-op if unavailable."""

    def __init__(self, model: str | None = None):
        self.enabled = False
        self._agent = None
        # Full pydantic-ai model string. ADAPTIVE_MODEL wins (e.g. "openai:gpt-4.1"
        # or "anthropic:claude-...."); otherwise fall back to google:<GEMINI_MODEL>.
        self.model = (
            model
            or os.getenv("ADAPTIVE_MODEL")
            or f"google:{os.getenv('GEMINI_MODEL', 'gemini-3.6-flash')}"
        )
        provider = self.model.split(":", 1)[0]
        key_env = {
            "google": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            "google-gla": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
            "openai": ("OPENAI_API_KEY",),
            "anthropic": ("ANTHROPIC_API_KEY",),
        }.get(provider, ())
        if key_env and not any(os.getenv(k) for k in key_env):
            log.info("no API key for '%s' -> adaptive layer disabled (deterministic-only)", provider)
            return
        try:
            from pydantic_ai import Agent
            self._agent = Agent(self.model, output_type=Diagnosis, system_prompt=_SYSTEM)
            self.enabled = True
            log.info("adaptive layer enabled (%s)", self.model)
        except Exception as exc:  # missing provider extra / bad model / import error
            log.info("adaptive layer unavailable (%s) -> disabled", exc)

    def diagnose(
        self,
        finding: Finding,
        brief: str,
        steps: list[Step],
        results: dict[str, StepResult],
        history: list[dict],
    ) -> Diagnosis | None:
        if not self.enabled:
            return None
        try:
            return self._agent.run_sync(_prompt(finding, brief, steps, results, history)).output
        except Exception as exc:
            log.warning("diagnose call failed: %s", exc)
            return None


def _prompt(
    finding: Finding,
    brief: str,
    steps: list[Step],
    results: dict[str, StepResult],
    history: list[dict],
) -> str:
    from .util import path_with_query

    path = path_with_query(finding.target.uri)
    observed = "\n".join(
        f"  - {r.id}: status={r.status} len={r.body_len} body[:140]={ (r.body or '')[:140]!r}"
        for r in results.values()
    )
    tried = "\n".join(
        f"  - {s.id}: {s.method} {s.path} params={s.params} json={s.json_body}" for s in steps
    )
    prior = "\n".join(
        f"  - attempt {h.get('n')}: {h.get('kind')} {h.get('reasoning') or h.get('oracle') or ''}"
        for h in history
    ) or "  (none)"

    return (
        f"FINDING\n"
        f"  class: {finding.vuln_class.value}\n"
        f"  path: {path}\n"
        f"  method: {finding.target.method}\n"
        f"  param: {finding.target.param}\n\n"
        f"DOMAIN BRIEF\n{brief or '  (none)'}\n\n"
        f"MARKER (embed this literal string in injected values so success is detectable): {SQLI_MARKER}\n\n"
        f"STEPS TRIED\n{tried}\n\n"
        f"OBSERVED\n{observed}\n\n"
        f"PRIOR ATTEMPTS\n{prior}\n\n"
        "Return ranked hypotheses (top-first) with concrete next_steps that reuse the "
        "path/param above, or give up with a non-confirmed verdict. Do not repeat a "
        "payload already tried."
    )
