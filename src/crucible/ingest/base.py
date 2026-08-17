"""The adapter contract every ingestion source must satisfy."""

from __future__ import annotations

from typing import Protocol

from ..models import Finding


class SourceAdapter(Protocol):
    """Turn a raw scanner report into a list of canonical `Finding`s.

    Implement this for each new source (ZAP, SARIF, Burp, a PDF extractor, ...).
    Keeping this contract tiny is what makes "ingest anything" true without
    touching the rest of the pipeline.
    """

    source_name: str

    def parse(self, raw_report: dict, target_base: str) -> list[Finding]:
        """Parse `raw_report`, keeping only findings for `target_base`'s host."""
        ...
