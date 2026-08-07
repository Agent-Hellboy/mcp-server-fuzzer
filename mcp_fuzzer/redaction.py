#!/usr/bin/env python3
"""Shared redaction helpers for credential-bearing values.

Anything the fuzzer shows a user or writes to disk (startup output, report
exports) funnels sensitive values through here, so a credential is never
copied verbatim into an artifact. Redaction is key-driven: only *values*
change, never keys, container types or structure.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Markers are matched against keys stripped of every non-alphanumeric
# character, so "api_key", "API-KEY" and "apiKey" all normalize to "apikey".
SENSITIVE_KEY_MARKERS = (
    "apikey",
    "authorization",
    "clientsecret",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "token",
)

# Keys whose string values are targets rather than secrets: the value is kept,
# but any credentials embedded in the URL are stripped. Matched on the
# normalized key ending, so "url" matches "server_url" but not "security".
URL_KEY_MARKERS = ("endpoint", "url", "uri")

_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]")

# Fallback for URLs that ``urlsplit`` refuses to parse: drop "user:pass@".
_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*://)[^/?#@]*@")


def is_sensitive_key(key: object) -> bool:
    """Return True when a mapping key names a credential-bearing value."""
    normalized = _NON_ALPHANUMERIC.sub("", str(key).lower())
    return any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)


def is_url_key(key: object) -> bool:
    """Return True when a mapping key names a URL-valued field."""
    normalized = _NON_ALPHANUMERIC.sub("", str(key).lower())
    return any(normalized.endswith(marker) for marker in URL_KEY_MARKERS)


def redact(value: Any, key: object | None = None) -> Any:
    """Return a display-safe copy of a JSON-like value.

    ``key`` is the mapping key ``value`` was stored under; when it names a
    secret the whole value (including a nested subtree) is replaced. A string
    stored under a URL-shaped key keeps its scheme/host/path and loses only the
    credentials inside it. Everything else is returned unchanged.
    """
    if key is not None and is_sensitive_key(key):
        return REDACTED
    if key is not None and isinstance(value, str) and is_url_key(key):
        return redact_url(value)
    if isinstance(value, dict):
        return {
            item_key: redact(item_value, item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def _redact_query(query: str) -> str:
    """Redact the values of sensitive parameters in a query-style string."""
    if not query:
        return query
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except ValueError:  # pragma: no cover - parse_qsl is very permissive
        return query
    if not any(is_sensitive_key(name) for name, _ in pairs):
        return query
    return urlencode(
        [
            (name, REDACTED if is_sensitive_key(name) else value)
            for name, value in pairs
        ],
        safe="[]",
    )


def redact_url(url: Any) -> Any:
    """Return ``url`` without credentials, still identifying the target.

    Strips ``user:pass@`` userinfo and the value of any query or fragment
    parameter whose name is sensitive (``?access_token=...``). Scheme, host,
    port and path are left intact, and a URL that carries no credentials is
    returned unchanged — including non-URL endpoints such as stdio commands.
    """
    if not isinstance(url, str) or not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _USERINFO.sub(r"\1", url)

    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    query = _redact_query(parts.query)
    fragment = parts.fragment
    if "=" in fragment:
        fragment = _redact_query(fragment)

    if (netloc, query, fragment) == (parts.netloc, parts.query, parts.fragment):
        return url
    return urlunsplit((parts.scheme, netloc, parts.path, query, fragment))


__all__ = [
    "REDACTED",
    "SENSITIVE_KEY_MARKERS",
    "URL_KEY_MARKERS",
    "is_sensitive_key",
    "is_url_key",
    "redact",
    "redact_url",
]
