"""Clean up raw findings before validation.

Two cheap, high-value steps:

* dedup identical (class, method, uri, param) findings, and
* optionally cap how many instances of the same class we validate, so one noisy
  rule (e.g. Backup File Disclosure x31) doesn't dominate the run time.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Finding


def _key(f: Finding) -> tuple:
    return (f.vuln_class, f.target.method, f.target.uri, f.target.param)


def normalize(findings: list[Finding], max_per_class: int | None = 8) -> list[Finding]:
    """Dedup findings and (optionally) cap instances per vulnerability class.

    Order is preserved. `max_per_class=None` disables the cap.
    """

    seen: set[tuple] = set()
    per_class: dict = defaultdict(int)
    out: list[Finding] = []

    for f in findings:
        k = _key(f)
        if k in seen:
            continue
        seen.add(k)

        if max_per_class is not None and per_class[f.vuln_class] >= max_per_class:
            continue
        per_class[f.vuln_class] += 1
        out.append(f)

    return out
