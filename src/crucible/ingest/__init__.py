"""Report ingestion: turn any scanner output into canonical `Finding`s.

Today only ZAP JSON is wired up, but everything downstream depends solely on the
`Finding` model, so adding SARIF / Burp / a PDF extractor later is just another
adapter that implements `SourceAdapter`.
"""

from .base import SourceAdapter
from .zap import ZapAdapter

__all__ = ["SourceAdapter", "ZapAdapter"]
