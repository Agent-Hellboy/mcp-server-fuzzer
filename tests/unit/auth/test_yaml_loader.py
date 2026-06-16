#!/usr/bin/env python3
"""Tests for YAML auth section loading."""

from __future__ import annotations

import pytest

from mcp_fuzzer.auth.yaml_loader import build_auth_from_yaml_section
from mcp_fuzzer.exceptions import AuthConfigError


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
