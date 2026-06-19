"""Tests for Docker/CI default CLI semantics."""

from __future__ import annotations

import argparse

from mcp_fuzzer.cli.config_merge import _apply_container_ci_defaults


def test_apply_container_ci_defaults_enables_fail_if_no_tools(monkeypatch):
    monkeypatch.setenv("MCP_FUZZER_IN_DOCKER", "1")
    args = argparse.Namespace(
        mode="tools", fail_if_no_tools=False, allow_empty_tools=False
    )
    _apply_container_ci_defaults(args)
    assert args.fail_if_no_tools is True


def test_apply_container_ci_defaults_respects_allow_empty_tools(monkeypatch):
    monkeypatch.setenv("MCP_FUZZER_IN_DOCKER", "1")
    args = argparse.Namespace(
        mode="tools", fail_if_no_tools=False, allow_empty_tools=True
    )
    _apply_container_ci_defaults(args)
    assert args.fail_if_no_tools is False
