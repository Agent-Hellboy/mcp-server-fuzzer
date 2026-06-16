"""OAuth metadata discovery for MCP authorization.

Implements:
- Protected Resource Metadata discovery (RFC 9728) -- locate the
  authorization server(s) for an MCP endpoint.
- Authorization Server Metadata discovery (RFC 8414 / OpenID Connect) --
  obtain the authorization/token/registration endpoints and capabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..discovery import (
    build_authorization_server_metadata_urls,
    build_protected_resource_metadata_urls,
    extract_resource_metadata_url,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0


@dataclass
class ProtectedResourceMetadata:
    """Parsed RFC 9728 Protected Resource Metadata document."""

    resource: str | None
    authorization_servers: list[str]
    scopes_supported: list[str]
    metadata_url: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthorizationServerMetadata:
    """Parsed RFC 8414 / OpenID Connect authorization server metadata."""

    issuer: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    registration_endpoint: str | None
    code_challenge_methods_supported: list[str]
    scopes_supported: list[str]
    grant_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    client_id_metadata_document_supported: bool
    metadata_url: str
    raw: dict[str, Any] = field(default_factory=dict)


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int))]
    return []


def _get_json(http: httpx.Client, url: str) -> dict[str, Any] | None:
    try:
        response = http.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        logger.debug("Metadata fetch failed for %s: %s", url, exc)
        return None
    if response.status_code != 200:
        logger.debug("Metadata fetch %s returned HTTP %s", url, response.status_code)
        return None
    try:
        data = response.json()
    except ValueError:
        logger.debug("Metadata fetch %s returned non-JSON body", url)
        return None
    return data if isinstance(data, dict) else None


def fetch_protected_resource_metadata(
    endpoint_url: str,
    www_authenticate: str | None = None,
    *,
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProtectedResourceMetadata | None:
    """Discover Protected Resource Metadata for an MCP endpoint (RFC 9728).

    Prefers the ``resource_metadata`` URL from the ``WWW-Authenticate`` header,
    otherwise falls back to the well-known URIs in spec-defined priority order.
    Returns ``None`` if no metadata document with ``authorization_servers``
    can be obtained.
    """
    candidates: list[str] = []
    header_url = extract_resource_metadata_url(www_authenticate)
    if header_url:
        candidates.append(header_url)
    candidates.extend(build_protected_resource_metadata_urls(endpoint_url))

    owns_client = http is None
    client = http or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        seen: set[str] = set()
        for url in candidates:
            if url in seen:
                continue
            seen.add(url)
            data = _get_json(client, url)
            if data is None:
                continue
            authorization_servers = _as_str_list(data.get("authorization_servers"))
            if not authorization_servers:
                logger.debug("RS metadata at %s lacks authorization_servers", url)
                continue
            return ProtectedResourceMetadata(
                resource=data.get("resource"),
                authorization_servers=authorization_servers,
                scopes_supported=_as_str_list(data.get("scopes_supported")),
                metadata_url=url,
                raw=data,
            )
    finally:
        if owns_client:
            client.close()
    return None


def fetch_authorization_server_metadata(
    issuer_url: str,
    *,
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AuthorizationServerMetadata | None:
    """Discover Authorization Server Metadata for an issuer (RFC 8414 / OIDC).

    Tries the well-known endpoints in the spec-defined priority order and
    returns the first document exposing a ``token_endpoint``.
    """
    owns_client = http is None
    client = http or httpx.Client(timeout=timeout, follow_redirects=True)
    try:
        for url in build_authorization_server_metadata_urls(issuer_url):
            data = _get_json(client, url)
            if data is None:
                continue
            if not data.get("token_endpoint") and not data.get(
                "authorization_endpoint"
            ):
                continue
            return AuthorizationServerMetadata(
                issuer=data.get("issuer"),
                authorization_endpoint=data.get("authorization_endpoint"),
                token_endpoint=data.get("token_endpoint"),
                registration_endpoint=data.get("registration_endpoint"),
                code_challenge_methods_supported=_as_str_list(
                    data.get("code_challenge_methods_supported")
                ),
                scopes_supported=_as_str_list(data.get("scopes_supported")),
                grant_types_supported=_as_str_list(
                    data.get("grant_types_supported")
                ),
                token_endpoint_auth_methods_supported=_as_str_list(
                    data.get("token_endpoint_auth_methods_supported")
                ),
                client_id_metadata_document_supported=bool(
                    data.get("client_id_metadata_document_supported")
                ),
                metadata_url=url,
                raw=data,
            )
    finally:
        if owns_client:
            client.close()
    return None


def verify_pkce_supported(metadata: AuthorizationServerMetadata) -> bool:
    """Return True if the authorization server advertises PKCE ``S256``.

    Per the MCP spec, clients MUST refuse to proceed when
    ``code_challenge_methods_supported`` is absent or lacks ``S256``.
    """
    return "S256" in metadata.code_challenge_methods_supported
