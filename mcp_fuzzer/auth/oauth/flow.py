"""High-level MCP authorization flow orchestrator.

Ties discovery, client registration, and the OAuth grant together into a
single ``run()`` that returns an :class:`OAuthToken`. Supports both the
user-delegated authorization-code+PKCE flow and the machine-to-machine
client_credentials grant, threading the RFC 8707 ``resource`` parameter
through every request.
"""

from __future__ import annotations

import logging
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from ...exceptions import AuthProviderError
from .authorization_code import (
    LoopbackRedirectServer,
    build_authorization_url,
    exchange_code_for_token,
    generate_state,
    refresh_access_token,
    request_client_credentials_token,
)
from .canonical import canonical_resource_uri
from .metadata import (
    AuthorizationServerMetadata,
    ProtectedResourceMetadata,
    fetch_authorization_server_metadata,
    fetch_protected_resource_metadata,
    verify_pkce_supported,
)
from .pkce import generate_pkce
from .registration import register_dynamic_client

logger = logging.getLogger(__name__)

GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_CLIENT_CREDENTIALS = "client_credentials"


@dataclass
class OAuthClientConfig:
    """Configuration for the MCP authorization flow."""

    grant_type: str = GRANT_AUTHORIZATION_CODE
    client_id: str | None = None
    client_secret: str | None = None
    scope: str | None = None
    redirect_path: str = "/callback"
    redirect_host: str = "127.0.0.1"
    redirect_port: int = 0
    client_name: str = "mcp-fuzzer"
    # Client ID Metadata Document URL (https) used as client_id when set.
    client_id_metadata_url: str | None = None
    # Skip discovery by providing endpoints directly (optional).
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    registration_endpoint: str | None = None
    timeout: float = 10.0
    callback_timeout: float = 120.0
    # Unattended fuzzers should not pop a browser by default -- the URL is
    # printed instead. Opt in with open_browser=True for interactive use.
    open_browser: bool = False


@dataclass
class OAuthToken:
    """An acquired OAuth access token plus refresh metadata."""

    access_token: str
    token_type: str = "Bearer"
    expires_at: float = 0.0
    refresh_token: str | None = None
    scope: str | None = None
    # Client id that obtained the token, persisted so a cached token can be
    # refreshed in a later run (e.g. dynamically-registered/CIMD clients).
    client_id: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_response(cls, payload: dict[str, Any]) -> "OAuthToken":
        expires_in = payload.get("expires_in")
        try:
            ttl = float(expires_in)
        except (TypeError, ValueError):
            ttl = 3600.0
        skew = min(60.0, max(ttl * 0.1, 1.0))
        return cls(
            access_token=str(payload["access_token"]),
            token_type=str(payload.get("token_type") or "Bearer"),
            expires_at=time.time() + max(ttl - skew, 1.0),
            refresh_token=payload.get("refresh_token"),
            scope=payload.get("scope"),
            raw=payload,
        )

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
            "client_id": self.client_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OAuthToken":
        return cls(
            access_token=str(data["access_token"]),
            token_type=str(data.get("token_type") or "Bearer"),
            expires_at=float(data.get("expires_at") or 0.0),
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            client_id=data.get("client_id"),
            raw=data,
        )


class MCPAuthorizationFlow:
    """Run the MCP OAuth 2.1 authorization flow for a single MCP endpoint."""

    def __init__(
        self,
        endpoint_url: str,
        config: OAuthClientConfig | None = None,
        *,
        www_authenticate: str | None = None,
        challenge_scopes: list[str] | None = None,
        http: httpx.Client | None = None,
        browser_opener: Callable[[str], Any] | None = None,
        redirect_server_factory: Callable[..., LoopbackRedirectServer] | None = None,
    ):
        self.endpoint_url = endpoint_url
        self.resource = canonical_resource_uri(endpoint_url)
        self.config = config or OAuthClientConfig()
        self.www_authenticate = www_authenticate
        self.challenge_scopes = challenge_scopes or []
        self._http = http
        self._browser_opener = browser_opener or webbrowser.open
        self._redirect_server_factory = (
            redirect_server_factory or LoopbackRedirectServer
        )
        self.rs_metadata: ProtectedResourceMetadata | None = None
        self.as_metadata: AuthorizationServerMetadata | None = None

    def _metadata_from_config(self) -> AuthorizationServerMetadata | None:
        """Build AS metadata directly from explicitly configured endpoints,
        bypassing discovery when the caller already knows them."""
        if not self.config.token_endpoint:
            return None
        return AuthorizationServerMetadata(
            issuer=self.config.issuer,
            authorization_endpoint=self.config.authorization_endpoint,
            token_endpoint=self.config.token_endpoint,
            registration_endpoint=self.config.registration_endpoint,
            # Assume S256 when endpoints are configured explicitly.
            code_challenge_methods_supported=["S256"],
            scopes_supported=[],
            grant_types_supported=[],
            token_endpoint_auth_methods_supported=[],
            client_id_metadata_document_supported=False,
            metadata_url="(configured)",
            raw={},
        )

    # -- discovery ---------------------------------------------------------
    def discover(self) -> AuthorizationServerMetadata:
        """Discover the protected-resource and authorization-server metadata."""
        configured = self._metadata_from_config()
        if configured is not None:
            self.as_metadata = configured
            return configured

        self.rs_metadata = fetch_protected_resource_metadata(
            self.endpoint_url,
            self.www_authenticate,
            http=self._http,
            timeout=self.config.timeout,
        )
        if self.rs_metadata is None:
            raise AuthProviderError(
                "Could not discover Protected Resource Metadata (RFC 9728) for "
                f"{self.endpoint_url}"
            )
        issuer = self.config.issuer
        if not issuer:
            if not self.rs_metadata.authorization_servers:
                raise AuthProviderError(
                    "Protected Resource Metadata lists no authorization_servers"
                )
            issuer = self.rs_metadata.authorization_servers[0]
        self.as_metadata = fetch_authorization_server_metadata(
            issuer, http=self._http, timeout=self.config.timeout
        )
        if self.as_metadata is None:
            raise AuthProviderError(
                f"Could not discover Authorization Server Metadata for {issuer}"
            )
        return self.as_metadata

    def _resolve_scope(self) -> str | None:
        # Per the MCP scope-selection strategy: explicit config, then the
        # WWW-Authenticate challenge scope, then the resource server's
        # scopes_supported (its minimal functional set). The AS scopes_supported
        # is a full catalogue, not a least-privilege set, so it is not used.
        if self.config.scope:
            return self.config.scope
        if self.challenge_scopes:
            return " ".join(self.challenge_scopes)
        if self.rs_metadata and self.rs_metadata.scopes_supported:
            return " ".join(self.rs_metadata.scopes_supported)
        return None

    def _resolve_client(
        self,
        as_metadata: AuthorizationServerMetadata,
        redirect_uri: str | None = None,
    ) -> tuple[str, str | None]:
        """Resolve a client_id (and optional secret) per the spec priority."""
        # 1. Pre-registered static client.
        if self.config.client_id:
            return self.config.client_id, self.config.client_secret
        # 2. Client ID Metadata Document (HTTPS URL as client_id).
        if self.config.client_id_metadata_url:
            if not as_metadata.client_id_metadata_document_supported:
                logger.warning(
                    "AS does not advertise client_id_metadata_document_supported; "
                    "attempting CIMD anyway"
                )
            return self.config.client_id_metadata_url, None
        # 3. Dynamic Client Registration -- register the *actual* redirect URI
        #    so it matches the authorization request (exact-match validation).
        if as_metadata.registration_endpoint:
            registration = register_dynamic_client(
                as_metadata.registration_endpoint,
                redirect_uris=[redirect_uri] if redirect_uri else [],
                client_name=self.config.client_name,
                scope=self._resolve_scope(),
                http=self._http,
                timeout=self.config.timeout,
            )
            return registration["client_id"], registration.get("client_secret")
        raise AuthProviderError(
            "No client credentials available: provide a client_id, a Client ID "
            "Metadata Document URL, or use an AS that supports dynamic registration"
        )

    # -- grants ------------------------------------------------------------
    def run(self) -> OAuthToken:
        as_metadata = self.discover()
        if self.config.grant_type == GRANT_CLIENT_CREDENTIALS:
            return self._run_client_credentials(as_metadata)
        return self._run_authorization_code(as_metadata)

    def _run_client_credentials(
        self, as_metadata: AuthorizationServerMetadata
    ) -> OAuthToken:
        if not as_metadata.token_endpoint:
            raise AuthProviderError("Authorization server has no token_endpoint")
        if not self.config.client_id:
            raise AuthProviderError(
                "client_credentials grant requires a client_id/client_secret"
            )
        payload = request_client_credentials_token(
            as_metadata.token_endpoint,
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            resource=self.resource,
            scope=self._resolve_scope(),
            http=self._http,
            timeout=self.config.timeout,
        )
        token = OAuthToken.from_response(payload)
        token.client_id = self.config.client_id
        return token

    def _run_authorization_code(
        self, as_metadata: AuthorizationServerMetadata
    ) -> OAuthToken:
        if not as_metadata.authorization_endpoint or not as_metadata.token_endpoint:
            raise AuthProviderError(
                "Authorization server is missing authorization/token endpoints"
            )
        if not verify_pkce_supported(as_metadata):
            raise AuthProviderError(
                "Authorization server does not advertise PKCE S256 support "
                "(code_challenge_methods_supported); refusing to proceed"
            )

        pkce = generate_pkce()
        state = generate_state()
        scope = self._resolve_scope()

        with self._redirect_server_factory(
            host=self.config.redirect_host,
            port=self.config.redirect_port,
            path=self.config.redirect_path,
        ) as server:
            # Resolve the client only once the loopback redirect URI is known,
            # so dynamic registration registers the exact redirect_uri used in
            # the authorization request.
            client_id, client_secret = self._resolve_client(
                as_metadata, redirect_uri=server.redirect_uri
            )
            auth_url = build_authorization_url(
                as_metadata.authorization_endpoint,
                client_id=client_id,
                redirect_uri=server.redirect_uri,
                code_challenge=pkce.challenge,
                state=state,
                resource=self.resource,
                scope=scope,
                code_challenge_method=pkce.method,
            )
            # Default: print the URL rather than hijacking the user's browser
            # mid-fuzz. Auto-open only when explicitly enabled (interactive use).
            logger.warning(
                "MCP authorization required. Open this URL to authorize the "
                "fuzzer (waiting up to %ss for the redirect):\n%s",
                int(self.config.callback_timeout),
                auth_url,
            )
            if self.config.open_browser:
                try:
                    self._browser_opener(auth_url)
                except Exception as exc:  # pragma: no cover - browser env specific
                    logger.warning("Could not open browser automatically: %s", exc)

            result = server.wait_for_callback(timeout=self.config.callback_timeout)

        if result.get("error"):
            raise AuthProviderError(
                f"Authorization failed: {result.get('error')} "
                f"{result.get('error_description', '')}".strip()
            )
        returned_state = result.get("state")
        if returned_state != state:
            raise AuthProviderError(
                "OAuth state mismatch -- possible CSRF; discarding response"
            )
        code = result.get("code")
        if not code:
            raise AuthProviderError("Authorization response did not include a code")

        payload = exchange_code_for_token(
            as_metadata.token_endpoint,
            code=code,
            code_verifier=pkce.verifier,
            client_id=client_id,
            redirect_uri=server.redirect_uri,
            resource=self.resource,
            client_secret=client_secret,
            http=self._http,
            timeout=self.config.timeout,
        )
        token = OAuthToken.from_response(payload)
        # Persist the resolved client so a cached token can later be refreshed.
        token.client_id = client_id
        self._resolved_client_id = client_id
        self._resolved_client_secret = client_secret
        return token

    def refresh(self, token: OAuthToken) -> OAuthToken:
        """Refresh an expired token if a refresh_token and token endpoint exist."""
        if not token.refresh_token or self.as_metadata is None:
            raise AuthProviderError("No refresh_token available")
        if not self.as_metadata.token_endpoint:
            raise AuthProviderError("Authorization server has no token_endpoint")
        client_id = (
            token.client_id
            or getattr(self, "_resolved_client_id", None)
            or self.config.client_id
        )
        client_secret = (
            getattr(self, "_resolved_client_secret", None)
            or self.config.client_secret
        )
        if not client_id:
            raise AuthProviderError("Cannot refresh without a client_id")
        payload = refresh_access_token(
            self.as_metadata.token_endpoint,
            refresh_token=token.refresh_token,
            client_id=client_id,
            resource=self.resource,
            scope=token.scope,
            client_secret=client_secret,
            http=self._http,
            timeout=self.config.timeout,
        )
        new_token = OAuthToken.from_response(payload)
        if not new_token.refresh_token:
            new_token.refresh_token = token.refresh_token
        return new_token
