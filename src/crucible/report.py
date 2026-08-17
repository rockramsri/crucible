"""Turn verdicts into a JSON report and a Markdown scorecard.

The scorecard is the headline: how many findings we confirmed, how many were
false positives, and the false-positive rate -- computed honestly (agent
failures, inconclusive, and skipped are excluded from the rate).
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .models import Verdict, VerdictType


def summarize(verdicts: list[Verdict]) -> dict:
    counts = Counter(v.verdict for v in verdicts)
    confirmed = counts[VerdictType.CONFIRMED]
    false_pos = counts[VerdictType.FALSE_POSITIVE]
    denom = confirmed + false_pos
    return {
        "total": len(verdicts),
        "confirmed": confirmed,
        "false_positive": false_pos,
        "inconclusive": counts[VerdictType.INCONCLUSIVE],
        "agent_failure": counts[VerdictType.AGENT_FAILURE],
        "skipped": counts[VerdictType.SKIPPED],
        # Rate is over decided findings only (confirmed + false_positive).
        "false_positive_rate": round(false_pos / denom, 3) if denom else None,
    }


def write_json(verdicts: list[Verdict], target: str, out_path: str) -> dict:
    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": summarize(verdicts),
        "verdicts": [v.model_dump() for v in verdicts],
    }
    Path(out_path).write_text(json.dumps(report, indent=2))
    return report


def scorecard_md(verdicts: list[Verdict], target: str) -> str:
    s = summarize(verdicts)
    fp_rate = "n/a" if s["false_positive_rate"] is None else f"{s['false_positive_rate'] * 100:.1f}%"
    lines = [
        f"# Validation scorecard - {target}",
        "",
        f"- Findings validated: {s['total']}",
        f"- Confirmed (true positives): {s['confirmed']}",
        f"- False positives: {s['false_positive']}",
        f"- False-positive rate: {fp_rate}  (over confirmed + false-positive only)",
        f"- Inconclusive: {s['inconclusive']}   Agent failures: {s['agent_failure']}   Skipped: {s['skipped']}",
        "",
        "| Finding | Class | Verdict | Why |",
        "| --- | --- | --- | --- |",
    ]
    for v in verdicts:
        reason = v.reason.replace("|", "\\|")
        lines.append(f"| {v.name} | {v.vuln_class.value} | {v.verdict.value} | {reason} |")
    return "\n".join(lines)
