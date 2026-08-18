"""The validation loop: plan -> run in sandbox -> oracle -> (adaptive) -> verdict.

Deterministic first: build the playbook's steps, run them, ask the oracle. If the
oracle can't decide (verdict is None) and the adaptive layer is enabled with
budget left, the LLM diagnoses WHY it failed, ranks hypotheses, and crafts the
next steps to try (best-first). The deterministic oracle re-judges every run --
the LLM never sets the verdict.

Everything each iteration does (payloads, responses, and the LLM's reasoning +
ranked hypotheses) is recorded on `Verdict.trace` for full auditability.
"""

from __future__ import annotations

import logging
import time

from .agent import RefineAgent
from .models import AttackPlan, Finding, Step, StepResult, Verdict, VerdictType
from .playbooks import get_playbook
from .playbooks.base import artifact

log = logging.getLogger("validator")

_REFERENCE_IDS = ("baseline", "control")   # non-attack steps kept across refinements


class Validator:
    def __init__(self, sandbox, agent: RefineAgent | None = None, max_attempts: int = 3):
        self.sandbox = sandbox
        self.agent = agent
        self.max_attempts = max_attempts   # total sandbox runs per finding

    def validate_all(self, findings: list[Finding]) -> list[Verdict]:
        return [self.validate(f) for f in findings]

    def validate(self, finding: Finding) -> Verdict:
        started = time.perf_counter()
        trace: list[dict] = []

        playbook = get_playbook(finding.vuln_class)
        if playbook is None:
            return self._verdict(finding, VerdictType.SKIPPED, "no playbook for this class",
                                 0, started, trace=trace)

        brief = getattr(playbook, "DOMAIN_BRIEF", "")
        steps = playbook.build_steps(finding, self.sandbox.target_base)
        reference = [s for s in steps if s.id in _REFERENCE_IDS]

        outcome = None
        results: dict[str, StepResult] = {}
        attempts = 0

        while attempts < self.max_attempts:
            attempts += 1
            mode = "deterministic" if attempts == 1 else "adaptive"
            try:
                results = self._run(finding, steps)
            except Exception as exc:
                log.warning("sandbox error for %s: %s", finding.id, exc)
                trace.append({"n": attempts, "kind": "run", "mode": mode, "error": str(exc)})
                return self._verdict(finding, VerdictType.AGENT_FAILURE,
                                     f"sandbox error: {exc}", attempts, started, trace=trace)

            outcome = playbook.oracle(finding, results)
            trace.append({
                "n": attempts, "kind": "run", "mode": mode,
                "steps": [{"id": s.id, "payload": _payload_of(s)} for s in steps if s.id not in _REFERENCE_IDS],
                "observed": {sid: {"status": r.status, "len": r.body_len} for sid, r in results.items()},
                "oracle": outcome.reason,
                "verdict": outcome.verdict.value if outcome.verdict else "unresolved",
            })
            log.info("  [%s attempt %d] %s -> %s", finding.id, attempts, mode,
                     outcome.verdict.value if outcome.verdict else "unresolved")

            if outcome.verdict is not None:
                break

            can_adapt = bool(self.agent and self.agent.enabled) and attempts < self.max_attempts
            if not can_adapt:
                if not self.agent:
                    skip = "adaptive did not run (disabled)"
                elif not self.agent.enabled:
                    skip = "adaptive did not run · LLM unavailable (no API key)"
                else:
                    skip = "budget exhausted · no further retries"
                _record_adaptive_skip(trace, attempts, skip)
                break

            # --- adaptive: diagnose why it failed and craft the next attempt ---
            diag = self.agent.diagnose(finding, brief, steps, results, trace)
            if diag is None:
                _record_adaptive_skip(trace, attempts, "LLM unavailable · diagnose call failed")
                break
            trace.append({
                "n": attempts, "kind": "diagnose",
                "reasoning": diag.reasoning,
                "hypotheses": [{"cause": h.cause, "confidence": h.confidence} for h in diag.hypotheses],
                "giveup": diag.giveup,
            })
            log.info("    LLM diagnosis: %s", (diag.reasoning or "")[:160])
            for h in diag.hypotheses[:3]:
                log.info("      hyp (%.2f): %s", h.confidence, h.cause[:120])

            gv = diag.safe_giveup_verdict()
            if diag.giveup and gv is not None:
                outcome = _giveup_outcome(gv, diag.giveup_reason)
                break
            top = next((h for h in diag.hypotheses if (h.next_steps or h.sweep)), None)
            if top is None:
                break
            # LLM picks the tactic; a 'sweep' is expanded deterministically by the
            # playbook (search is code's job, not the LLM's). Keep baseline for the diff.
            if top.sweep is not None and hasattr(playbook, "expand_sweep"):
                crafted = playbook.expand_sweep(finding, top.sweep.breakouts, top.sweep.max_columns)
                log.info("    trying hypothesis: %s  (sweep -> %d steps)", top.cause[:90], len(crafted))
            else:
                crafted = top.next_steps
                log.info("    trying hypothesis: %s  (%d steps)", top.cause[:90], len(crafted))
            steps = reference + crafted

        if outcome is None or outcome.verdict is None:
            reason = outcome.reason if outcome else "no oracle result"
            return self._verdict(finding, VerdictType.INCONCLUSIVE, reason, attempts, started, trace=trace)

        proof = [artifact(s, results[s.id]) for s in steps
                 if s.id in outcome.proof_steps and s.id in results]
        return self._verdict(finding, outcome.verdict, outcome.reason, attempts, started,
                             proof=proof, trace=trace)

    def _run(self, finding: Finding, steps: list[Step]) -> dict[str, StepResult]:
        plan = AttackPlan(
            finding_id=finding.id, vuln_class=finding.vuln_class,
            target_base=self.sandbox.target_base,
            hypothesis=f"{finding.vuln_class.value} at {finding.target.uri}",
            steps=steps,
        )
        return self.sandbox.run(plan).by_id()

    def _verdict(self, finding, vtype, reason, attempts, started, proof=None, trace=None) -> Verdict:
        return Verdict(
            finding_id=finding.id, vuln_class=finding.vuln_class, name=finding.name,
            verdict=vtype, reason=reason, attempts=attempts,
            elapsed_s=round(time.perf_counter() - started, 2),
            proof=proof or [], trace=trace or [],
        )


def _record_adaptive_skip(trace: list[dict], attempts: int, reason: str) -> None:
    """Keep a diagnose node in the lineage even when the LLM never ran.

    The UI draws the budget-gate / LLM branch from this trace entry (and from
    oracle.interim). Without it, a settle-to-inconclusive event used to wipe
    the extra nodes so the graph collapsed back to a single deterministic lane.
    """
    trace.append({
        "n": attempts,
        "kind": "diagnose",
        "reasoning": reason,
        "hypotheses": [{"cause": reason, "confidence": 0.0}],
        "giveup": True,
    })
    log.info("    adaptive skip: %s", reason)


def _payload_of(step: Step) -> str:
    if step.params:
        return " ".join(f"{k}={v}" for k, v in step.params.items())
    if step.json_body:
        return str(step.json_body)
    return step.path


def _giveup_outcome(vtype: VerdictType, reason: str):
    from .playbooks.base import OracleOutcome
    return OracleOutcome(vtype, reason or "classified by adaptive layer")
