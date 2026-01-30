#!/usr/bin/env python3
"""
Unit tests for ConfigPort interface coverage.
"""

import pytest

from mcp_fuzzer.client.ports.config_port import ConfigPort

pytestmark = [pytest.mark.unit, pytest.mark.client]


class DummyConfig(ConfigPort):
    def __init__(self):
        self._values = {}

    def get(self, key, default=None):
        return self._values.get(key, default)

    def set(self, key, value):
        self._values[key] = value

    def update(self, config_dict):
        self._values.update(config_dict)

    def load_file(self, file_path):
        return {"path": file_path}

    def apply_file(self, config_path=None, search_paths=None, file_names=None):
        return bool(config_path or search_paths or file_names)

    def get_schema(self):
        return {"type": "object"}


def test_config_port_contract():
    config = DummyConfig()
    config.set("key", "value")
    assert config.get("key") == "value"
    config.update({"other": 2})
    assert config.get("other") == 2
    assert config.get("missing", "fallback") == "fallback"
    assert config.load_file("config.toml") == {"path": "config.toml"}
    assert config.apply_file(config_path="config.toml") is True
    assert config.apply_file() is False
    assert config.get_schema() == {"type": "object"}
