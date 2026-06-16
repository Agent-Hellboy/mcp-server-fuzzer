"""``AuthProvider`` that authenticates against an MCP authorization server.

Lazily runs :class:`MCPAuthorizationFlow` on first use, caches the resulting
token (in memory and, by default, on disk), and transparently refreshes it when
it expires. The on-disk cache means the browser-based authorization-code step
happens at most once -- subsequent fuzzing runs reuse or silently refresh the
token. Plugs into the existing :class:`~mcp_fuzzer.auth.manager.AuthManager`.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

import httpx

from ...exceptions import AuthProviderError
from ..providers import AuthProvider
from .flow import (
    GRANT_CLIENT_CREDENTIALS,
    MCPAuthorizationFlow,
    OAuthClientConfig,
    OAuthToken,
)
from .token_store import TokenStore

logger = logging.getLogger(__name__)


class MCPOAuthProvider(AuthProvider):
    """Acquire and attach MCP OAuth 2.1 bearer tokens for a single endpoint."""

    def __init__(
        self,
        endpoint_url: str,
        config: OAuthClientConfig | None = None,
        *,
        www_authenticate: str | None = None,
        challenge_scopes: list[str] | None = None,
        http: httpx.Client | None = None,
        browser_opener: Callable[[str], Any] | None = None,
        token_store: TokenStore | None = None,
        use_token_cache: bool = True,
    ):
        self.endpoint_url = endpoint_url
        self.config = config or OAuthClientConfig()
        self._www_authenticate = www_authenticate
        self._challenge_scopes = challenge_scopes
        self._http = http
        self._browser_opener = browser_opener
        self._token: OAuthToken | None = None
        self._flow: MCPAuthorizationFlow | None = None
        self._lock = threading.Lock()
        self._store = token_store if token_store is not None else (
            TokenStore() if use_token_cache else None
        )

    def _cache_key(self) -> tuple[str, str, str | None]:
        return (self.endpoint_url, self.config.grant_type, self.config.client_id)

    def _build_flow(self) -> MCPAuthorizationFlow:
        return MCPAuthorizationFlow(
            self.endpoint_url,
            self.config,
            www_authenticate=self._www_authenticate,
            challenge_scopes=self._challenge_scopes,
            http=self._http,
            browser_opener=self._browser_opener,
        )

    def _load_cached(self) -> OAuthToken | None:
        if self._store is None:
            return None
        data = self._store.load(*self._cache_key())
        if not data:
            return None
        try:
            return OAuthToken.from_dict(data)
        except (KeyError, ValueError, TypeError):
            return None

    def _persist(self, token: OAuthToken) -> None:
        if self._store is not None:
            self._store.save(*self._cache_key(), token.to_dict())

    def _ensure_token(self) -> OAuthToken:
        with self._lock:
            if self._token is None:
                self._token = self._load_cached()

            if self._token is not None and not self._token.is_expired():
                return self._token

            # Try a refresh first if we have a usable refresh token.
            if self._token is not None and self._token.refresh_token:
                if self._flow is None:
                    self._flow = self._build_flow()
                try:
                    if self._flow.as_metadata is None:
                        self._flow.discover()
                    self._token = self._flow.refresh(self._token)
                    self._persist(self._token)
                    return self._token
                except AuthProviderError as exc:
                    logger.info("Token refresh failed, re-running flow: %s", exc)

            self._flow = self._build_flow()
            self._token = self._flow.run()
            self._persist(self._token)
            return self._token

    def get_auth_headers(self) -> dict[str, str]:
        token = self._ensure_token()
        return {"Authorization": f"{token.token_type} {token.access_token}"}

    def get_auth_params(self) -> dict[str, Any]:
        return {}

    def invalidate(self) -> None:
        """Drop cached tokens so the next request re-authorizes (e.g. on 401)."""
        with self._lock:
            self._token = None
            if self._store is not None:
                self._store.clear(*self._cache_key())


def create_mcp_oauth_auth(
    endpoint_url: str,
    *,
    grant_type: str = "authorization_code",
    client_id: str | None = None,
    client_secret: str | None = None,
    scope: str | None = None,
    client_id_metadata_url: str | None = None,
    open_browser: bool = False,
    use_token_cache: bool = True,
    **config_kwargs: Any,
) -> MCPOAuthProvider:
    """Convenience factory for an :class:`MCPOAuthProvider`."""
    if grant_type == GRANT_CLIENT_CREDENTIALS and not client_id:
        raise AuthProviderError(
            "client_credentials grant requires a client_id and client_secret"
        )
    config = OAuthClientConfig(
        grant_type=grant_type,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        client_id_metadata_url=client_id_metadata_url,
        open_browser=open_browser,
        **config_kwargs,
    )
    return MCPOAuthProvider(endpoint_url, config, use_token_cache=use_token_cache)
