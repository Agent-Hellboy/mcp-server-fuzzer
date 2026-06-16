"""OAuth 2.1 Authorization Code grant primitives (with PKCE + RFC 8707).

Includes a small loopback HTTP server used to capture the authorization-code
redirect, matching how desktop MCP clients (Cursor/Claude/Codex) implement the
browser-based flow against a ``http://localhost:<port>/callback`` redirect URI.
"""

from __future__ import annotations

import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from ...exceptions import AuthProviderError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0


def generate_state() -> str:
    """Generate an unguessable OAuth ``state`` value (CSRF protection)."""
    return secrets.token_urlsafe(24)


def build_authorization_url(
    authorization_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    resource: str,
    scope: str | None = None,
    code_challenge_method: str = "S256",
    extra_params: dict[str, str] | None = None,
) -> str:
    """Build the authorization request URL (auth code + PKCE + resource)."""
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
        "resource": resource,
    }
    if scope:
        params["scope"] = scope
    if extra_params:
        # Never let caller extras overwrite security-critical parameters.
        for key, value in extra_params.items():
            if key not in params:
                params[key] = value
    sep = "&" if urlsplit(authorization_endpoint).query else "?"
    return f"{authorization_endpoint}{sep}{urlencode(params)}"


def _post_token_request(
    token_endpoint: str,
    data: dict[str, str],
    *,
    client_secret: str | None,
    client_id: str,
    http: httpx.Client | None,
    timeout: float,
) -> dict[str, Any]:
    owns_client = http is None
    # Token endpoints must not redirect: a 307/308 would replay the POST body
    # (authorization code, refresh token, or client secret) to the new target.
    client = http or httpx.Client(timeout=timeout, follow_redirects=False)
    # Confidential clients authenticate with HTTP Basic; public clients send
    # client_id in the body (token_endpoint_auth_method = none).
    auth = (client_id, client_secret) if client_secret else None
    if not client_secret:
        data = {**data, "client_id": client_id}
    try:
        response = client.post(
            token_endpoint,
            data=data,
            auth=auth,
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise AuthProviderError(f"Token request failed: {exc}") from exc
    finally:
        if owns_client:
            client.close()

    if response.status_code != 200:
        raise AuthProviderError(
            f"Token request failed: HTTP {response.status_code}: "
            f"{response.text[:300]}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise AuthProviderError("Token response was not valid JSON") from exc
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise AuthProviderError("Token response missing 'access_token'")
    return payload


def exchange_code_for_token(
    token_endpoint: str,
    *,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
    client_secret: str | None = None,
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Exchange an authorization code for tokens (with PKCE verifier + resource)."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "resource": resource,
    }
    return _post_token_request(
        token_endpoint,
        data,
        client_secret=client_secret,
        client_id=client_id,
        http=http,
        timeout=timeout,
    )


def refresh_access_token(
    token_endpoint: str,
    *,
    refresh_token: str,
    client_id: str,
    resource: str,
    scope: str | None = None,
    client_secret: str | None = None,
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Redeem a refresh token for a fresh access token (RFC 8707 resource)."""
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "resource": resource,
    }
    if scope:
        data["scope"] = scope
    return _post_token_request(
        token_endpoint,
        data,
        client_secret=client_secret,
        client_id=client_id,
        http=http,
        timeout=timeout,
    )


def request_client_credentials_token(
    token_endpoint: str,
    *,
    client_id: str,
    client_secret: str | None,
    resource: str,
    scope: str | None = None,
    http: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Obtain a token via the ``client_credentials`` grant (RFC 8707 resource)."""
    if not client_secret:
        raise AuthProviderError(
            "client_credentials grant requires a client_secret "
            "(confidential client authentication)"
        )
    data = {"grant_type": "client_credentials", "resource": resource}
    if scope:
        data["scope"] = scope
    return _post_token_request(
        token_endpoint,
        data,
        client_secret=client_secret,
        client_id=client_id,
        http=http,
        timeout=timeout,
    )


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - required name
        parsed = urlsplit(self.path)
        server: Any = self.server
        # Ignore unrelated probes (e.g. /favicon.ico) so they cannot satisfy
        # the wait with an empty/garbage result.
        expected = getattr(server, "expected_path", None)
        if expected is not None and parsed.path != expected:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        query = parse_qs(parsed.query)
        server.oauth_result = {key: values[0] for key, values in query.items()}
        body = (
            b"<html><body><h2>Authorization complete.</h2>"
            b"You may close this window and return to the fuzzer.</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:  # silence stdlib request logging
        return


class LoopbackRedirectServer:
    """A one-shot localhost HTTP server that captures the OAuth redirect.

    Usage::

        with LoopbackRedirectServer() as server:
            open_browser(build_authorization_url(..., redirect_uri=server.redirect_uri))
            result = server.wait_for_callback(timeout=120)
            code, state = result["code"], result.get("state")
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, path: str = "/callback"):
        self._path = path if path.startswith("/") else f"/{path}"
        self._server = HTTPServer((host, port), _CallbackHandler)
        self._server.oauth_result = None  # type: ignore[attr-defined]
        self._server.expected_path = self._path  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None
        bound_host, bound_port = self._server.server_address[:2]
        self.host = str(bound_host)
        self.port = int(bound_port)

    @property
    def redirect_uri(self) -> str:
        return f"http://{self.host}:{self.port}{self._path}"

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def wait_for_callback(self, timeout: float = 120.0) -> dict[str, str]:
        """Block until the redirect arrives; return its query parameters."""
        if self._thread is None:
            self.start()
        deadline = threading.Event()
        # Poll the result with a bounded wait without busy-spinning hard.
        waited = 0.0
        step = 0.1
        while waited < timeout:
            result = getattr(self._server, "oauth_result", None)
            if result is not None:
                return result
            deadline.wait(step)
            waited += step
        raise AuthProviderError(
            "Timed out waiting for the OAuth authorization redirect"
        )

    def close(self) -> None:
        # shutdown() only works (and only avoids deadlock) when serve_forever
        # is running in another thread; skip it if we never started.
        if self._thread is not None:
            self._server.shutdown()
            self._thread.join(timeout=2.0)
            self._thread = None
        self._server.server_close()

    def __enter__(self) -> "LoopbackRedirectServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
