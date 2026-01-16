#!/usr/bin/env python3
"""Tests for ConfigPort abstract interface."""

import pytest

from mcp_fuzzer.client.ports.config_port import ConfigPort


def test_config_port_is_abstract():
    """Test that ConfigPort cannot be instantiated directly."""
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        ConfigPort()
