#!/usr/bin/env python3
"""Tests for the MCP OAuth 2.1 authorization client (MCP 2025-11-25 spec)."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from mcp_fuzzer.auth.oauth import (
    OAuthClientConfig,
    MCPAuthorizationFlow,
    MCPOAuthProvider,
    build_authorization_url,
    canonical_resource_uri,
    exchange_code_for_token,
    fetch_authorization_server_metadata,
    fetch_protected_resource_metadata,
    generate_pkce,
    refresh_access_token,
    register_dynamic_client,
    verify_pkce_supported,
)
from mcp_fuzzer.auth.oauth.authorization_code import (
    LoopbackRedirectServer,
    request_client_credentials_token,
)
from mcp_fuzzer.exceptions import AuthProviderError


# --- pure helpers -----------------------------------------------------------


def test_generate_pkce_s256_roundtrip():
    pkce = generate_pkce()
    assert pkce.method == "S256"
    assert 43 <= len(pkce.verifier) <= 128
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pkce.verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    assert pkce.challenge == expected


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("HTTPS://MCP.Example.com:8443/mcp/", "https://mcp.example.com:8443/mcp"),
        ("https://mcp.example.com/", "https://mcp.example.com"),
        ("https://mcp.example.com/server/mcp", "https://mcp.example.com/server/mcp"),
        ("https://mcp.example.com#frag", "https://mcp.example.com"),
    ],
)
def test_canonical_resource_uri(raw, expected):
    assert canonical_resource_uri(raw) == expected


def test_canonical_resource_uri_requires_scheme():
    with pytest.raises(ValueError):
        canonical_resource_uri("mcp.example.com")


def test_build_authorization_url_includes_required_params():
    url = build_authorization_url(
        "https://auth.example.com/authorize",
        client_id="client123",
        redirect_uri="http://127.0.0.1:5000/callback",
        code_challenge="abc",
        state="xyz",
        resource="https://mcp.example.com/mcp",
        scope="files:read",
    )
    query = parse_qs(urlsplit(url).query)
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["client123"]
    assert query["redirect_uri"] == ["http://127.0.0.1:5000/callback"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == ["abc"]
    assert query["state"] == ["xyz"]
    assert query["resource"] == ["https://mcp.example.com/mcp"]
    assert query["scope"] == ["files:read"]


# --- discovery --------------------------------------------------------------


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetch_protected_resource_metadata_from_well_known():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/oauth-protected-resource":
            return httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com",
                    "authorization_servers": ["https://auth.example.com"],
                    "scopes_supported": ["files:read", "files:write"],
                },
            )
        return httpx.Response(404)

    with _mock_client(handler) as http:
        meta = fetch_protected_resource_metadata(
            "https://mcp.example.com/mcp", http=http
        )
    assert meta is not None
    assert meta.authorization_servers == ["https://auth.example.com"]
    assert meta.scopes_supported == ["files:read", "files:write"]


def test_fetch_protected_resource_metadata_prefers_header_url():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/custom-meta":
            return httpx.Response(
                200,
                json={"authorization_servers": ["https://auth.example.com"]},
            )
        return httpx.Response(404)

    header = 'Bearer resource_metadata="https://mcp.example.com/custom-meta"'
    with _mock_client(handler) as http:
        meta = fetch_protected_resource_metadata(
            "https://mcp.example.com/mcp", header, http=http
        )
    assert meta is not None
    assert seen[0] == "/custom-meta"


def test_fetch_protected_resource_metadata_requires_authorization_servers():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"resource": "https://mcp.example.com"})

    with _mock_client(handler) as http:
        meta = fetch_protected_resource_metadata(
            "https://mcp.example.com/mcp", http=http
        )
    assert meta is None


def test_fetch_authorization_server_metadata_and_pkce_support():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/oauth-authorization-server":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "registration_endpoint": "https://auth.example.com/register",
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["files:read"],
                    "client_id_metadata_document_supported": True,
                },
            )
        return httpx.Response(404)

    with _mock_client(handler) as http:
        meta = fetch_authorization_server_metadata(
            "https://auth.example.com", http=http
        )
    assert meta is not None
    assert meta.token_endpoint == "https://auth.example.com/token"
    assert meta.registration_endpoint == "https://auth.example.com/register"
    assert verify_pkce_supported(meta) is True
    assert meta.client_id_metadata_document_supported is True


def test_verify_pkce_unsupported_when_methods_absent():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
            },
        )

    with _mock_client(handler) as http:
        meta = fetch_authorization_server_metadata(
            "https://auth.example.com", http=http
        )
    assert verify_pkce_supported(meta) is False


# --- registration & token requests -----------------------------------------


def test_register_dynamic_client():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/register"
        return httpx.Response(201, json={"client_id": "dyn-123", "client_secret": "s"})

    with _mock_client(handler) as http:
        result = register_dynamic_client(
            "https://auth.example.com/register",
            redirect_uris=["http://127.0.0.1:0/callback"],
            http=http,
        )
    assert result["client_id"] == "dyn-123"


def test_register_dynamic_client_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad request")

    with _mock_client(handler) as http:
        with pytest.raises(AuthProviderError, match="registration failed"):
            register_dynamic_client(
                "https://auth.example.com/register",
                redirect_uris=["http://127.0.0.1:0/callback"],
                http=http,
            )


def test_resolve_client_retries_registration_without_scope():
    """A registration rejected for naming scopes is retried without scope."""
    from mcp_fuzzer.auth.oauth import AuthorizationServerMetadata

    attempts: list[bool] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.content.decode())
        has_scope = "scope" in body
        attempts.append(has_scope)
        if has_scope:
            # Locked-down realm: rejects anonymous registration naming scopes.
            return httpx.Response(403, text="insufficient_scope")
        return httpx.Response(201, json={"client_id": "dyn-noscope"})

    as_metadata = AuthorizationServerMetadata(
        issuer="https://auth.example.com",
        authorization_endpoint="https://auth.example.com/authorize",
        token_endpoint="https://auth.example.com/token",
        registration_endpoint="https://auth.example.com/register",
        code_challenge_methods_supported=["S256"],
        scopes_supported=[],
        grant_types_supported=[],
        token_endpoint_auth_methods_supported=[],
        client_id_metadata_document_supported=False,
        metadata_url="https://auth.example.com/.well-known/oauth-authorization-server",
        raw={},
    )

    with _mock_client(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(scope="openid profile email"),
            http=http,
        )
        client_id, client_secret = flow._resolve_client(
            as_metadata, redirect_uri="http://127.0.0.1:5000/callback"
        )

    assert client_id == "dyn-noscope"
    assert client_secret is None
    # First attempt carried the scope (rejected), second omitted it (accepted).
    assert attempts == [True, False]


def test_exchange_code_includes_pkce_and_resource():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(parse_qs(request.content.decode())))
        return httpx.Response(
            200,
            json={"access_token": "tok", "token_type": "Bearer", "expires_in": 3600},
        )

    with _mock_client(handler) as http:
        payload = exchange_code_for_token(
            "https://auth.example.com/token",
            code="authcode",
            code_verifier="verifier",
            client_id="client123",
            redirect_uri="http://127.0.0.1:5000/callback",
            resource="https://mcp.example.com/mcp",
            http=http,
        )
    assert payload["access_token"] == "tok"
    assert captured["code_verifier"] == ["verifier"]
    assert captured["resource"] == ["https://mcp.example.com/mcp"]
    assert captured["grant_type"] == ["authorization_code"]
    # public client: client_id is sent in the body
    assert captured["client_id"] == ["client123"]


def test_client_credentials_token_includes_resource():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(parse_qs(request.content.decode())))
        return httpx.Response(200, json={"access_token": "cc-tok", "expires_in": 600})

    with _mock_client(handler) as http:
        payload = request_client_credentials_token(
            "https://auth.example.com/token",
            client_id="svc",
            client_secret="secret",
            resource="https://mcp.example.com/mcp",
            scope="api",
            http=http,
        )
    assert payload["access_token"] == "cc-tok"
    assert captured["grant_type"] == ["client_credentials"]
    assert captured["resource"] == ["https://mcp.example.com/mcp"]
    assert captured["scope"] == ["api"]


def test_refresh_access_token():
    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(parse_qs(request.content.decode()))
        assert body["grant_type"] == ["refresh_token"]
        assert body["resource"] == ["https://mcp.example.com/mcp"]
        return httpx.Response(200, json={"access_token": "tok2", "expires_in": 3600})

    with _mock_client(handler) as http:
        payload = refresh_access_token(
            "https://auth.example.com/token",
            refresh_token="rt",
            client_id="client123",
            resource="https://mcp.example.com/mcp",
            http=http,
        )
    assert payload["access_token"] == "tok2"


# --- loopback redirect server -----------------------------------------------


def test_loopback_redirect_server_captures_callback():
    with LoopbackRedirectServer() as server:
        uri = server.redirect_uri
        assert uri.startswith("http://127.0.0.1:")
        httpx.get(f"{uri}?code=abc&state=xyz", timeout=5.0)
        result = server.wait_for_callback(timeout=5.0)
    assert result == {"code": "abc", "state": "xyz"}


# --- end-to-end flow --------------------------------------------------------


class _FakeRedirectServer:
    """Records the auth URL's state and replays it as the callback."""

    def __init__(self, **_kwargs):
        self.redirect_uri = "http://127.0.0.1:7777/callback"
        self.captured_state: str | None = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wait_for_callback(self, timeout=120.0):
        return {"code": "authcode", "state": self.captured_state}


def _as_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/.well-known/oauth-protected-resource/mcp":
        return httpx.Response(
            200, json={"authorization_servers": ["https://auth.example.com"]}
        )
    if path == "/.well-known/oauth-protected-resource":
        return httpx.Response(
            200, json={"authorization_servers": ["https://auth.example.com"]}
        )
    if path == "/.well-known/oauth-authorization-server":
        return httpx.Response(
            200,
            json={
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/authorize",
                "token_endpoint": "https://auth.example.com/token",
                "registration_endpoint": "https://auth.example.com/register",
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["files:read"],
            },
        )
    if path == "/register":
        return httpx.Response(201, json={"client_id": "dyn-client"})
    if path == "/token":
        return httpx.Response(
            200,
            json={
                "access_token": "final-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-1",
            },
        )
    return httpx.Response(404)


def test_full_authorization_code_flow_with_dcr():
    server = _FakeRedirectServer()

    def opener(url: str):
        server.captured_state = parse_qs(urlsplit(url).query)["state"][0]

    with _mock_client(_as_handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(open_browser=True),
            http=http,
            browser_opener=opener,
            redirect_server_factory=lambda **kw: server,
        )
        token = flow.run()

    assert token.access_token == "final-token"
    assert token.refresh_token == "refresh-1"
    assert flow.resource == "https://mcp.example.com/mcp"


def test_authorization_code_flow_state_mismatch_aborts():
    server = _FakeRedirectServer()
    server.captured_state = "attacker-state"

    with _mock_client(_as_handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(open_browser=False),
            http=http,
            browser_opener=lambda url: None,
            redirect_server_factory=lambda **kw: server,
        )
        with pytest.raises(AuthProviderError, match="state mismatch"):
            flow.run()


def test_client_credentials_flow():
    with _mock_client(_as_handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(
                grant_type="client_credentials",
                client_id="svc",
                client_secret="secret",
            ),
            http=http,
        )
        token = flow.run()
    assert token.access_token == "final-token"


def test_flow_refuses_without_pkce_support():
    def handler(request: httpx.Request) -> httpx.Response:
        if "protected-resource" in request.url.path:
            return httpx.Response(
                200, json={"authorization_servers": ["https://auth.example.com"]}
            )
        if "authorization-server" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                },
            )
        return httpx.Response(404)

    with _mock_client(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(client_id="pre", open_browser=False),
            http=http,
        )
        with pytest.raises(AuthProviderError, match="PKCE"):
            flow.run()


def test_provider_caches_and_invalidates_token():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            calls["count"] += 1
        return _as_handler(request)

    with _mock_client(handler) as http:
        provider = MCPOAuthProvider(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(
                grant_type="client_credentials",
                client_id="svc",
                client_secret="secret",
            ),
            http=http,
            use_token_cache=False,
        )
        headers1 = provider.get_auth_headers()
        headers2 = provider.get_auth_headers()
        assert headers1 == {"Authorization": "Bearer final-token"}
        assert calls["count"] == 1  # cached on the second call
        provider.invalidate()
        provider.get_auth_headers()
        assert calls["count"] == 2  # re-acquired after invalidate


def test_token_store_persists_across_providers(tmp_path):
    from mcp_fuzzer.auth.oauth.token_store import TokenStore

    store = TokenStore(cache_dir=tmp_path)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            calls["count"] += 1
        return _as_handler(request)

    config = OAuthClientConfig(
        grant_type="client_credentials", client_id="svc", client_secret="secret"
    )
    with _mock_client(handler) as http:
        first = MCPOAuthProvider(
            "https://mcp.example.com/mcp", config, http=http, token_store=store
        )
        first.get_auth_headers()
        # A brand-new provider (e.g. next fuzzing run) reuses the cached token.
        second = MCPOAuthProvider(
            "https://mcp.example.com/mcp", config, http=http, token_store=store
        )
        headers = second.get_auth_headers()

    assert headers == {"Authorization": "Bearer final-token"}
    assert calls["count"] == 1  # second provider hit the disk cache, no new token


# --- review-hardening regressions ------------------------------------------


def test_authorization_url_extras_cannot_override_reserved():
    url = build_authorization_url(
        "https://auth.example.com/authorize",
        client_id="client123",
        redirect_uri="http://127.0.0.1:5000/callback",
        code_challenge="abc",
        state="real-state",
        resource="https://mcp.example.com/mcp",
        extra_params={"state": "attacker", "prompt": "consent"},
    )
    query = parse_qs(urlsplit(url).query)
    assert query["state"] == ["real-state"]  # reserved param not overridden
    assert query["prompt"] == ["consent"]  # genuine extra still added


def test_client_credentials_requires_secret():
    with pytest.raises(AuthProviderError, match="client_secret"):
        request_client_credentials_token(
            "https://auth.example.com/token",
            client_id="svc",
            client_secret=None,
            resource="https://mcp.example.com/mcp",
        )


def test_cimd_url_must_have_https_and_path():
    from mcp_fuzzer.auth.oauth import build_client_id_metadata_document

    with pytest.raises(AuthProviderError):
        build_client_id_metadata_document(
            "https://example.com", redirect_uris=["http://127.0.0.1:0/callback"]
        )
    with pytest.raises(AuthProviderError):
        build_client_id_metadata_document(
            "http://example.com/client.json",
            redirect_uris=["http://127.0.0.1:0/callback"],
        )
    doc = build_client_id_metadata_document(
        "https://example.com/client.json",
        redirect_uris=["http://127.0.0.1:0/callback"],
    )
    assert doc["client_id"] == "https://example.com/client.json"


def test_token_roundtrip_preserves_client_id():
    from mcp_fuzzer.auth.oauth import OAuthToken

    token = OAuthToken(access_token="t", client_id="dyn-client", refresh_token="r")
    restored = OAuthToken.from_dict(token.to_dict())
    assert restored.client_id == "dyn-client"


def test_flow_uses_configured_endpoints_without_discovery():
    # token_endpoint configured directly -> no RS/AS metadata fetch needed.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "cfg-tok"})
        return httpx.Response(404)

    with _mock_client(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(
                grant_type="client_credentials",
                client_id="svc",
                client_secret="secret",
                token_endpoint="https://auth.example.com/token",
            ),
            http=http,
        )
        token = flow.run()
    assert token.access_token == "cfg-tok"
    assert flow.rs_metadata is None  # discovery skipped


def test_loopback_ignores_unrelated_paths():
    with LoopbackRedirectServer() as server:
        base = f"http://{server.host}:{server.port}"
        # A probe to a different path must not satisfy the wait.
        resp = httpx.get(f"{base}/favicon.ico", timeout=5.0)
        assert resp.status_code == 404
        httpx.get(f"{base}/callback?code=abc&state=xyz", timeout=5.0)
        result = server.wait_for_callback(timeout=5.0)
    assert result == {"code": "abc", "state": "xyz"}
