"""On-disk token cache so the browser authorization step happens at most once.

For an unattended fuzzer, repeatedly opening a browser is unacceptable. Caching
the acquired token (and refresh token) lets the authorization-code flow run once;
later runs reuse the cached token and refresh it silently. Tokens are sensitive,
so the cache file is created with owner-only (0600) permissions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def default_cache_dir() -> Path:
    """Return the per-user cache directory for OAuth tokens."""
    base = os.getenv("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return Path(base) / "mcp-fuzzer" / "oauth"


def _cache_key(endpoint_url: str, grant_type: str, client_id: str | None) -> str:
    raw = f"{endpoint_url}|{grant_type}|{client_id or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class TokenStore:
    """JSON-file token cache keyed by (endpoint, grant, client_id)."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or default_cache_dir()

    def _path(self, endpoint_url: str, grant_type: str, client_id: str | None) -> Path:
        key = _cache_key(endpoint_url, grant_type, client_id)
        return self.cache_dir / f"{key}.json"

    def load(
        self, endpoint_url: str, grant_type: str, client_id: str | None
    ) -> dict | None:
        path = self._path(endpoint_url, grant_type, client_id)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def save(
        self,
        endpoint_url: str,
        grant_type: str,
        client_id: str | None,
        payload: dict,
    ) -> None:
        path = self._path(endpoint_url, grant_type, client_id)
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            # Write with owner-only permissions.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
        except OSError as exc:
            logger.debug("Could not persist OAuth token cache: %s", exc)

    def clear(
        self, endpoint_url: str, grant_type: str, client_id: str | None
    ) -> None:
        path = self._path(endpoint_url, grant_type, client_id)
        try:
            path.unlink()
        except OSError:
            pass
