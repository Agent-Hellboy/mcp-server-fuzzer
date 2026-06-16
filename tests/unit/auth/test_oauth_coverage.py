#!/usr/bin/env python3
"""Branch coverage for the MCP OAuth client (error paths, refresh, cache)."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from mcp_fuzzer.auth.oauth import (
    MCPAuthorizationFlow,
    MCPOAuthProvider,
    OAuthClientConfig,
    OAuthToken,
    build_client_id_metadata_document,
    create_mcp_oauth_auth,
    exchange_code_for_token,
    fetch_authorization_server_metadata,
    fetch_protected_resource_metadata,
    refresh_access_token,
    register_dynamic_client,
)
from mcp_fuzzer.auth.oauth.token_store import TokenStore, default_cache_dir
from mcp_fuzzer.exceptions import AuthProviderError


def _mock(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# --- metadata error branches ----------------------------------------------


def test_fetch_as_metadata_http_error_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    with _mock(handler) as http:
        assert fetch_authorization_server_metadata("https://auth", http=http) is None


def test_fetch_rs_metadata_non_json_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    with _mock(handler) as http:
        assert (
            fetch_protected_resource_metadata("https://mcp.x/mcp", http=http) is None
        )


def test_fetch_as_metadata_skips_doc_without_token_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"authorization_endpoint": "https://a/auth"})

    with _mock(handler) as http:
        assert fetch_authorization_server_metadata("https://auth", http=http) is None


# --- token request error branches ------------------------------------------


def test_exchange_code_non_200_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad")

    with _mock(handler) as http:
        with pytest.raises(AuthProviderError, match="Token request failed"):
            exchange_code_for_token(
                "https://a/token",
                code="c",
                code_verifier="v",
                client_id="id",
                redirect_uri="http://127.0.0.1:0/cb",
                resource="https://mcp.x/mcp",
                http=http,
            )


def test_exchange_code_missing_access_token_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"nope": 1})

    with _mock(handler) as http:
        with pytest.raises(AuthProviderError, match="access_token"):
            exchange_code_for_token(
                "https://a/token",
                code="c",
                code_verifier="v",
                client_id="id",
                redirect_uri="http://127.0.0.1:0/cb",
                resource="https://mcp.x/mcp",
                http=http,
            )


def test_refresh_access_token_sends_scope():
    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(parse_qs(request.content.decode()))
        assert body["scope"] == ["s1 s2"]
        return httpx.Response(200, json={"access_token": "fresh"})

    with _mock(handler) as http:
        payload = refresh_access_token(
            "https://a/token",
            refresh_token="r",
            client_id="id",
            resource="https://mcp.x/mcp",
            scope="s1 s2",
            http=http,
        )
    assert payload["access_token"] == "fresh"


# --- registration error branches + CIMD ------------------------------------


def test_register_non_json_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, text="x")

    with _mock(handler) as http:
        with pytest.raises(AuthProviderError, match="non-JSON"):
            register_dynamic_client(
                "https://a/register",
                redirect_uris=["http://127.0.0.1:0/cb"],
                http=http,
            )


def test_register_missing_client_id_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"no": "id"})

    with _mock(handler) as http:
        with pytest.raises(AuthProviderError, match="client_id"):
            register_dynamic_client(
                "https://a/register",
                redirect_uris=["http://127.0.0.1:0/cb"],
                http=http,
            )


def test_cimd_includes_client_uri():
    doc = build_client_id_metadata_document(
        "https://e.com/client.json",
        redirect_uris=["http://127.0.0.1:0/cb"],
        client_uri="https://e.com",
    )
    assert doc["client_uri"] == "https://e.com"
    assert doc["redirect_uris"] == ["http://127.0.0.1:0/cb"]


# --- token store ------------------------------------------------------------


def test_token_store_default_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert str(tmp_path) in str(default_cache_dir())


def test_token_store_save_load_clear(tmp_path):
    store = TokenStore(tmp_path)
    assert store.load("e", "g", "c") is None
    store.save("e", "g", "c", {"access_token": "t"})
    assert store.load("e", "g", "c") == {"access_token": "t"}
    store.clear("e", "g", "c")
    assert store.load("e", "g", "c") is None
    # clearing a missing entry is a no-op
    store.clear("e", "g", "missing")


# --- flow discover / grant error branches ----------------------------------


def test_discover_without_rs_metadata_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    with _mock(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.x/mcp", OAuthClientConfig(), http=http
        )
        with pytest.raises(AuthProviderError, match="Protected Resource Metadata"):
            flow.discover()


def test_discover_without_as_metadata_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        if "protected-resource" in request.url.path:
            return httpx.Response(
                200, json={"authorization_servers": ["https://auth"]}
            )
        return httpx.Response(404)

    with _mock(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.x/mcp", OAuthClientConfig(), http=http
        )
        with pytest.raises(AuthProviderError, match="Authorization Server Metadata"):
            flow.discover()


def test_client_credentials_requires_client_id():
    flow = MCPAuthorizationFlow(
        "https://mcp.x/mcp",
        OAuthClientConfig(
            grant_type="client_credentials",
            token_endpoint="https://auth/token",
        ),
    )
    with pytest.raises(AuthProviderError, match="client_id"):
        flow.run()


def test_flow_refresh_without_refresh_token_raises():
    flow = MCPAuthorizationFlow(
        "https://mcp.x/mcp",
        OAuthClientConfig(client_id="c", token_endpoint="https://auth/token"),
    )
    flow.discover()
    with pytest.raises(AuthProviderError, match="No refresh_token"):
        flow.refresh(OAuthToken(access_token="x"))


def test_flow_refresh_uses_persisted_client_id():
    def handler(request: httpx.Request) -> httpx.Response:
        body = dict(parse_qs(request.content.decode()))
        assert body["grant_type"] == ["refresh_token"]
        assert body["client_id"] == ["persisted"]
        return httpx.Response(200, json={"access_token": "refreshed", "expires_in": 60})

    with _mock(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.x/mcp",
            OAuthClientConfig(token_endpoint="https://auth/token"),
            http=http,
        )
        flow.discover()
        old = OAuthToken(
            access_token="old", refresh_token="r", client_id="persisted", expires_at=0
        )
        new = flow.refresh(old)
    assert new.access_token == "refreshed"
    assert new.refresh_token == "r"  # preserved across refresh


# --- provider refresh + factory --------------------------------------------


def test_provider_refreshes_expired_cached_token(tmp_path):
    store = TokenStore(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "new", "expires_in": 3600})
        return httpx.Response(404)

    config = OAuthClientConfig(
        grant_type="client_credentials",
        client_id="svc",
        client_secret="secret",
        token_endpoint="https://auth.example.com/token",
    )
    with _mock(handler) as http:
        provider = MCPOAuthProvider(
            "https://mcp.x/mcp", config, http=http, token_store=store
        )
        # Seed an expired token (with refresh token) under the provider's key.
        store.save(
            *provider._cache_key(),
            {
                "access_token": "old",
                "expires_at": 0,
                "refresh_token": "r",
                "client_id": "svc",
            },
        )
        headers = provider.get_auth_headers()
    assert headers == {"Authorization": "Bearer new"}


def test_create_mcp_oauth_auth_client_credentials_requires_client_id():
    with pytest.raises(AuthProviderError, match="client_id"):
        create_mcp_oauth_auth(
            "https://mcp.x/mcp", grant_type="client_credentials"
        )


def test_create_mcp_oauth_auth_returns_provider():
    provider = create_mcp_oauth_auth(
        "https://mcp.x/mcp",
        grant_type="client_credentials",
        client_id="svc",
        client_secret="secret",
    )
    assert isinstance(provider, MCPOAuthProvider)
    assert provider.get_auth_params() == {}


def test_loopback_wait_times_out():
    from mcp_fuzzer.auth.oauth.authorization_code import LoopbackRedirectServer

    server = LoopbackRedirectServer()
    try:
        with pytest.raises(AuthProviderError, match="Timed out"):
            server.wait_for_callback(timeout=0.2)
    finally:
        server.close()


def test_loopback_close_without_start_is_safe():
    from mcp_fuzzer.auth.oauth.authorization_code import LoopbackRedirectServer

    server = LoopbackRedirectServer()
    server.close()  # never started serve_forever -> must not deadlock


def test_fetch_rs_metadata_transport_error_returns_none():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with _mock(handler) as http:
        assert (
            fetch_protected_resource_metadata("https://mcp.x/mcp", http=http) is None
        )


def test_register_transport_error_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with _mock(handler) as http:
        with pytest.raises(AuthProviderError, match="registration request failed"):
            register_dynamic_client(
                "https://a/register",
                redirect_uris=["http://127.0.0.1:0/cb"],
                http=http,
            )


def test_provider_reauthorizes_when_refresh_fails(tmp_path):
    store = TokenStore(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            body = dict(parse_qs(request.content.decode()))
            if body.get("grant_type") == ["refresh_token"]:
                return httpx.Response(400, text="expired")
            return httpx.Response(
                200, json={"access_token": "reauth", "expires_in": 60}
            )
        return httpx.Response(404)

    config = OAuthClientConfig(
        grant_type="client_credentials",
        client_id="svc",
        client_secret="secret",
        token_endpoint="https://auth.example.com/token",
    )
    with _mock(handler) as http:
        provider = MCPOAuthProvider(
            "https://mcp.x/mcp", config, http=http, token_store=store
        )
        store.save(
            *provider._cache_key(),
            {
                "access_token": "old",
                "expires_at": 0,
                "refresh_token": "r",
                "client_id": "svc",
            },
        )
        headers = provider.get_auth_headers()
    assert headers == {"Authorization": "Bearer reauth"}


class _FakeRedirect:
    def __init__(self, **_kw):
        self.redirect_uri = "http://127.0.0.1:7788/callback"
        self.captured_state = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wait_for_callback(self, timeout=120.0):
        return {"code": "authcode", "state": self.captured_state}


def test_authorization_code_flow_browser_opener_failure_is_non_fatal():
    server = _FakeRedirect()

    def opener(url):
        from urllib.parse import urlsplit as _split

        server.captured_state = parse_qs(_split(url).query)["state"][0]
        raise RuntimeError("no browser here")  # must be swallowed

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "protected-resource" in path:
            return httpx.Response(
                200, json={"authorization_servers": ["https://auth.example.com"]}
            )
        if "authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "registration_endpoint": "https://auth.example.com/register",
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        if path == "/register":
            return httpx.Response(201, json={"client_id": "dyn"})
        if path == "/token":
            return httpx.Response(
                200,
                json={
                    "access_token": "tok",
                    "expires_in": 60,
                    "refresh_token": "r",
                },
            )
        return httpx.Response(404)

    with _mock(handler) as http:
        flow = MCPAuthorizationFlow(
            "https://mcp.example.com/mcp",
            OAuthClientConfig(open_browser=True),
            http=http,
            browser_opener=opener,
            redirect_server_factory=lambda **kw: server,
        )
        token = flow.run()
    assert token.access_token == "tok"
    assert token.client_id == "dyn"  # persisted resolved client
