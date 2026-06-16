#!/usr/bin/env python3
"""Tests for YAML auth section loading."""

from __future__ import annotations

import pytest

from mcp_fuzzer.auth.yaml_loader import (
    _provider_entry_to_dict,
    build_auth_from_yaml_section,
)
from mcp_fuzzer.exceptions import AuthConfigError, AuthProviderError


def test_build_auth_from_yaml_list_providers_with_mappings():
    manager = build_auth_from_yaml_section(
        {
            "providers": [
                {
                    "id": "api",
                    "type": "api_key",
                    "config": {"api_key": "secret-key"},
                }
            ],
            "mappings": {"echo": "api"},
        }
    )
    assert "api" in manager.auth_providers
    assert manager.get_auth_params_for_tool("echo") == {}


def test_build_auth_from_yaml_dict_providers():
    manager = build_auth_from_yaml_section(
        {
            "providers": {
                "basic": {"type": "basic", "username": "u", "password": "p"},
            },
            "tool_mapping": {"tool_a": "basic"},
        }
    )
    headers = manager.auth_providers["basic"].get_auth_headers()
    assert headers["Authorization"].startswith("Basic ")


def test_build_auth_from_yaml_all_list_provider_types():
    manager = build_auth_from_yaml_section(
        {
            "providers": [
                {
                    "id": "api",
                    "type": "api_key",
                    "api_key": "key",
                    "header_name": "X-API-Key",
                    "prefix": "",
                },
                {
                    "id": "basic",
                    "type": "basic",
                    "username": "u",
                    "password": "p",
                },
                {
                    "id": "oauth",
                    "type": "oauth",
                    "token": "tok",
                    "token_type": "Bearer",
                },
                {
                    "id": "cc",
                    "type": "oauth_client_credentials",
                    "token_url": "https://auth/token",
                    "client_id": "id",
                    "client_secret": "secret",
                    "scope": "read",
                },
                {
                    "id": "custom",
                    "type": "custom",
                    "headers": {"X-Test": "1"},
                },
            ],
            "default_provider": "api",
        }
    )
    assert set(manager.auth_providers) == {"api", "basic", "oauth", "cc", "custom"}
    assert manager.default_provider == "api"
    assert manager.auth_providers["custom"].get_auth_headers() == {"X-Test": "1"}


def test_provider_entry_to_dict_uses_inline_fields_when_config_missing():
    name, config = _provider_entry_to_dict(
        {"id": "api", "type": "api_key", "api_key": "inline"}
    )
    assert name == "api"
    assert config["api_key"] == "inline"


def test_build_auth_rejects_unknown_mapping_provider():
    with pytest.raises(AuthConfigError, match="unknown provider"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {
                        "id": "api",
                        "type": "api_key",
                        "config": {"api_key": "k"},
                    }
                ],
                "mappings": {"tool": "missing"},
            }
        )


def test_build_auth_rejects_non_object_section():
    with pytest.raises(AuthConfigError, match="auth section must be an object"):
        build_auth_from_yaml_section(["not", "a", "dict"])


def test_build_auth_rejects_invalid_providers_type():
    with pytest.raises(AuthConfigError, match="providers"):
        build_auth_from_yaml_section({"providers": "bad"})


def test_build_auth_rejects_provider_missing_id():
    with pytest.raises(AuthConfigError, match="requires an 'id'"):
        build_auth_from_yaml_section(
            {"providers": [{"type": "api_key", "api_key": "k"}]}
        )


def test_build_auth_rejects_provider_missing_type():
    with pytest.raises(AuthConfigError, match="missing 'type'"):
        build_auth_from_yaml_section(
            {"providers": [{"id": "api", "api_key": "k"}]}
        )


def test_build_auth_rejects_non_object_provider_config():
    with pytest.raises(AuthConfigError, match="config must be an object"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {"id": "api", "type": "api_key", "config": "bad"},
                ]
            }
        )


def test_build_auth_rejects_unknown_provider_type():
    with pytest.raises(AuthProviderError, match="Unknown provider type"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {"id": "x", "type": "nope", "config": {}},
                ]
            }
        )


def test_build_auth_rejects_custom_headers_not_dict():
    with pytest.raises(AuthConfigError, match="custom headers must be a dict"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {
                        "id": "custom",
                        "type": "custom",
                        "headers": "bad",
                    }
                ]
            }
        )


def test_build_auth_rejects_invalid_tool_mapping_type():
    with pytest.raises(AuthConfigError, match="tool_mapping"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {"id": "api", "type": "api_key", "api_key": "k"},
                ],
                "tool_mapping": "bad",
            }
        )


def test_build_auth_rejects_non_object_provider_entry():
    with pytest.raises(AuthConfigError, match="must be an object"):
        build_auth_from_yaml_section(
            {"providers": ["not-a-provider-object"]}
        )


def test_build_auth_rejects_unknown_default_provider():
    with pytest.raises(AuthConfigError, match="default_provider"):
        build_auth_from_yaml_section(
            {
                "providers": [
                    {"id": "api", "type": "api_key", "api_key": "k"},
                ],
                "default_provider": "missing",
            }
        )

