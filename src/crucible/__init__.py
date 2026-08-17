"""Crucible.

An agentic validation layer that takes a scanner report (ZAP today, anything
later), re-exploits each finding inside an ephemeral sandbox, and reports a
verdict (true positive / false positive / ...) with proof and a measured
false-positive rate.

The pipeline is deliberately simple to read end to end:

    ingest -> normalize -> plan (playbook) -> run in sandbox -> oracle -> report

Nothing "decides" a finding is real except a deterministic oracle. The LLM (if
enabled) only proposes payloads or classifies failures; it never declares
success.
"""

__version__ = "0.1.0"
