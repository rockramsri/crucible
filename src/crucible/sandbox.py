"""Ephemeral sandboxes that execute an AttackPlan and return raw results.

Two backends, one interface (`run(plan) -> RunResult`):

* DockerSandbox -- the real thing: one locked-down, no-internet container per
  plan (cap-drop ALL, read-only rootfs, memory/pids caps), talking to the target
  over the private `pentest` network, destroyed automatically (`--rm`).
* LocalSandbox  -- runs the same `verify.py` as a host subprocess. Handy for
  development and as the documented fallback when Docker is unavailable.

The LLM and the oracle live OUTSIDE this module; the sandbox only runs steps.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .models import AttackPlan, RunResult, StepResult

_RUNNER_DIR = Path(__file__).parent / "runner"
_VERIFY = _RUNNER_DIR / "verify.py"
_IMAGE = "crucible-runner"


def _parse(stdout: str) -> RunResult:
    data = json.loads(stdout)
    return RunResult(
        finding_id=data.get("finding_id", ""),
        results=[StepResult(**r) for r in data.get("results", [])],
    )


def _plan_json(plan: AttackPlan, target_base: str) -> str:
    payload = plan.model_dump()
    payload["target_base"] = target_base   # the sandbox decides how to reach the target
    return json.dumps(payload)


class LocalSandbox:
    """Run verify.py in a host subprocess (dev / fallback)."""

    backend = "local"

    def __init__(self, target_base: str = "http://localhost:3000"):
        self.target_base = target_base

    def run(self, plan: AttackPlan) -> RunResult:
        proc = subprocess.run(
            [sys.executable, str(_VERIFY)],
            input=_plan_json(plan, self.target_base),
            capture_output=True, text=True, timeout=150,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"verify.py failed: {proc.stderr.strip()}")
        return _parse(proc.stdout)


class DockerSandbox:
    """Run each plan in a fresh, hardened, no-internet container."""

    backend = "docker"

    def __init__(self, target_base: str = "http://juiceshop:3000", network: str = "pentest"):
        self.target_base = target_base
        self.network = network
        self._ensure_image()

    def _ensure_image(self) -> None:
        have = subprocess.run(["docker", "image", "inspect", _IMAGE],
                              capture_output=True, text=True)
        if have.returncode == 0:
            return
        build = subprocess.run(["docker", "build", "-t", _IMAGE, str(_RUNNER_DIR)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            raise RuntimeError(f"failed to build runner image:\n{build.stderr}")

    def run(self, plan: AttackPlan) -> RunResult:
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i",
             "--network", self.network,
             "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges",
             "--read-only",
             "--memory", "512m",
             "--pids-limit", "128",
             _IMAGE],
            input=_plan_json(plan, self.target_base),
            capture_output=True, text=True, timeout=210,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"sandbox container failed: {proc.stderr.strip()}")
        return _parse(proc.stdout)


def make_sandbox(backend: str, target_base: str | None = None):
    """Factory: 'docker' (default) or 'local'."""
    if backend == "local":
        return LocalSandbox(target_base or "http://localhost:3000")
    return DockerSandbox(target_base or "http://juiceshop:3000")
