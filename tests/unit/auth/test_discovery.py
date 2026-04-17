#!/usr/bin/env python3
"""Unit tests for authorization discovery helpers."""

import pytest

from mcp_fuzzer.auth.discovery import (
    build_authorization_server_metadata_urls,
    build_protected_resource_metadata_urls,
    extract_requested_scopes,
    extract_resource_metadata_url,
    parse_www_authenticate,
)


pytestmark = [pytest.mark.unit, pytest.mark.auth]


def test_parse_www_authenticate_extracts_bearer_params():
    header = (
        'Bearer resource_metadata="https://mcp.example.com/meta", '
        'scope="files:read files:write"'
    )

    parsed = parse_www_authenticate(header)

    assert parsed == [
        {
            "scheme": "Bearer",
            "params": {
                "resource_metadata": "https://mcp.example.com/meta",
                "scope": "files:read files:write",
            },
        }
    ]


def test_extract_resource_metadata_and_scopes():
    header = (
        'Bearer resource_metadata="https://mcp.example.com/meta", '
        'scope="files:read files:write"'
    )

    assert extract_resource_metadata_url(header) == "https://mcp.example.com/meta"
    assert extract_requested_scopes(header) == ["files:read", "files:write"]


def test_build_protected_resource_metadata_urls_prefers_endpoint_path():
    urls = build_protected_resource_metadata_urls("https://mcp.example.com/public/mcp")

    assert urls == [
        "https://mcp.example.com/.well-known/oauth-protected-resource/public/mcp",
        "https://mcp.example.com/.well-known/oauth-protected-resource",
    ]


def test_build_authorization_server_metadata_urls_with_path():
    urls = build_authorization_server_metadata_urls("https://auth.example.com/tenant1")

    assert urls == [
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_build_authorization_server_metadata_urls_without_path():
    urls = build_authorization_server_metadata_urls("https://auth.example.com")

    assert urls == [
        "https://auth.example.com/.well-known/oauth-authorization-server",
        "https://auth.example.com/.well-known/openid-configuration",
    ]
