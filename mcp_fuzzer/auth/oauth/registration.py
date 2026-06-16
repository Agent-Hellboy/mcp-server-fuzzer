"""OAuth client registration approaches for MCP.

Supports the two automatable mechanisms the MCP spec describes:

- Dynamic Client Registration (RFC 7591) -- ``POST`` to the AS
  ``registration_endpoint`` to obtain a ``client_id``.
- Client ID Metadata Documents -- build the JSON document that lets a client
  use an HTTPS URL as its ``client_id``.

Pre-registration (static ``client_id``/``client_secret``) needs no helper --
the values are supplied directly to the flow.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

import httpx

from ...exceptions import AuthProviderError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0


def register_dynamic_client(
    registration_endpoint: str,
    *,
    redirect_uris: list[str],
    client_name: str = "mcp-fuzzer",
    grant_types: list[str] | None = None,
    response_types: list[str] | None = None,
    scope: str | None = None,
    token_endpoint_auth_method: str = "none",
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register an OAuth client via RFC 7591 and return the response document.

    The returned dict contains at least ``client_id`` (and ``client_secret``
    for confidential clients). Raises ``AuthProviderError`` on failure.
    """
    payload: dict[str, Any] = dict(extra) if extra else {}
    # Registered metadata fields take precedence over caller-supplied extras.
    payload.update(
        {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types or ["authorization_code", "refresh_token"],
            "response_types": response_types or ["code"],
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }
    )
    if scope:
        payload["scope"] = scope

    owns_client = http is None
    # Registration endpoints must not redirect: a 307/308 would replay the POST
    # body (which may carry sensitive metadata) to the new target.
    client = http or httpx.Client(timeout=timeout, follow_redirects=False)
    try:
        response = client.post(
            registration_endpoint,
            json=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise AuthProviderError(
            f"Dynamic client registration request failed: {exc}"
        ) from exc
    finally:
        if owns_client:
            client.close()

    if response.status_code not in (200, 201):
        raise AuthProviderError(
            "Dynamic client registration failed: HTTP "
            f"{response.status_code}: {response.text[:300]}"
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise AuthProviderError(
            "Dynamic client registration returned non-JSON response"
        ) from exc
    if not isinstance(data, dict) or not data.get("client_id"):
        raise AuthProviderError(
            "Dynamic client registration response missing 'client_id'"
        )
    return data


def build_client_id_metadata_document(
    client_id_url: str,
    *,
    client_name: str = "mcp-fuzzer",
    redirect_uris: list[str],
    client_uri: str | None = None,
    grant_types: list[str] | None = None,
    response_types: list[str] | None = None,
    token_endpoint_auth_method: str = "none",
) -> dict[str, Any]:
    """Build a Client ID Metadata Document (CIMD).

    ``client_id`` MUST equal the HTTPS document URL exactly and the URL MUST
    use the ``https`` scheme with a path component.
    """
    parsed = urlsplit(client_id_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path in ("", "/"):
        raise AuthProviderError(
            "Client ID Metadata Document URL must be an https URL with a host "
            f"and a path component, got {client_id_url!r}"
        )
    document: dict[str, Any] = {
        "client_id": client_id_url,
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types or ["authorization_code", "refresh_token"],
        "response_types": response_types or ["code"],
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }
    if client_uri:
        document["client_uri"] = client_uri
    return document
