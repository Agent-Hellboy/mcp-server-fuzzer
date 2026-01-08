"""Tests for client settings utilities."""

import pytest

from mcp_fuzzer.client.settings import CliConfig, ClientSettings


def test_cli_config_to_client_settings():
    args = object()
    cfg = CliConfig(args=args, merged={"a": 1})
    cs = cfg.to_client_settings()
    assert isinstance(cs, ClientSettings)
    assert cs.data["a"] == 1


def test_client_settings_get_and_attr():
    cs = ClientSettings({"x": 5})
    assert cs.get("x") == 5
    with pytest.raises(AttributeError):
        _ = cs.missing  # type: ignore[attr-defined]
