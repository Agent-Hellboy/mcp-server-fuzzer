#!/usr/bin/env python3
"""Tests for shim template helpers."""

from __future__ import annotations

import pytest

from mcp_fuzzer.safety_system.blocking.shims import load_shim_template

pytestmark = [pytest.mark.unit]


def test_load_shim_template_reads_default_shim():
    template = load_shim_template("default_shim.py")
    assert "[FUZZER BLOCKED]" in template


def test_load_shim_template_raises_for_missing_file():
    with pytest.raises(FileNotFoundError):
        load_shim_template("does-not-exist.txt")
