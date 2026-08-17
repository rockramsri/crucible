"""Tiny helpers shared across the package (kept dependency-free on purpose)."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def path_with_query(uri: str) -> str:
    """Return just the path + query of a URL (drop scheme and host).

    The scanner reports absolute URLs like ``http://juiceshop:3000/rest/...`` but
    the sandbox talks to a configurable base (``juiceshop:3000`` in Docker,
    ``localhost:3000`` on the host), so we only ever keep the path + query.

        >>> path_with_query("http://juiceshop:3000/rest/products/search?q=a")
        '/rest/products/search?q=a'
    """

    parts = urlsplit(uri)
    if not parts.scheme and not parts.netloc:
        # Already a relative path.
        return uri if uri.startswith("/") else "/" + uri
    return urlunsplit(("", "", parts.path or "/", parts.query, "")) or "/"


def looks_like_spa(status: int | None, headers: dict, body: str) -> bool:
    """Heuristic: did we get the Angular single-page app shell instead of a file?

    Juice Shop serves its SPA (index.html) for many unknown paths, so a 200 that
    is really just the app shell must NOT be treated as a disclosed file.
    """

    if status != 200:
        return False
    ctype = str(headers.get("content-type", "")).lower()
    if "text/html" not in ctype:
        return False
    sniff = body[:2000].lower()
    return "<app-root" in sniff or "id=\"main-content\"" in sniff or "owasp juice shop" in sniff
