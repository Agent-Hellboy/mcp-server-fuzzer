#!/usr/bin/env python3
"""Unit tests for configuration constants."""

from __future__ import annotations

import pytest

from mcp_fuzzer.config import (
    DEFAULT_FORCE_KILL_TIMEOUT,
    DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_PROTOCOL_RUNS_PER_TYPE,
    DEFAULT_PROTOCOL_VERSION,
    DEFAULT_TIMEOUT,
    DEFAULT_TOOL_RUNS,
    DEFAULT_TOOL_TIMEOUT,
    PROCESS_CLEANUP_TIMEOUT,
    PROCESS_FORCE_KILL_TIMEOUT,
    PROCESS_TERMINATION_TIMEOUT,
    PROCESS_WAIT_TIMEOUT,
    SAFETY_ENV_ALLOWLIST,
    SAFETY_HEADER_DENYLIST,
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_PROXY_ENV_DENYLIST,
)


def test_process_constants_exported():
    """Test that PROCESS_* constants are properly exported."""
    assert PROCESS_TERMINATION_TIMEOUT == 0.5
    assert PROCESS_FORCE_KILL_TIMEOUT == 1.0
    assert PROCESS_CLEANUP_TIMEOUT == 5.0
    assert PROCESS_WAIT_TIMEOUT == 1.0
    assert isinstance(PROCESS_TERMINATION_TIMEOUT, float)
    assert isinstance(PROCESS_FORCE_KILL_TIMEOUT, float)
    assert isinstance(PROCESS_CLEANUP_TIMEOUT, float)
    assert isinstance(PROCESS_WAIT_TIMEOUT, float)


def test_safety_no_network_default():
    """Test that SAFETY_NO_NETWORK_DEFAULT is properly documented."""
    # The constant should be False (allow network by default)
    # with a clear comment explaining it
    assert SAFETY_NO_NETWORK_DEFAULT is False
    assert isinstance(SAFETY_NO_NETWORK_DEFAULT, bool)


def test_safety_local_hosts():
    """Test that SAFETY_LOCAL_HOSTS contains expected local hosts."""
    assert "localhost" in SAFETY_LOCAL_HOSTS
    assert "127.0.0.1" in SAFETY_LOCAL_HOSTS
    assert "::1" in SAFETY_LOCAL_HOSTS
    assert isinstance(SAFETY_LOCAL_HOSTS, set)


def test_safety_header_denylist():
    """Test that SAFETY_HEADER_DENYLIST contains sensitive headers."""
    assert "authorization" in SAFETY_HEADER_DENYLIST
    assert "cookie" in SAFETY_HEADER_DENYLIST
    assert isinstance(SAFETY_HEADER_DENYLIST, set)


def test_safety_proxy_env_denylist():
    """Test that SAFETY_PROXY_ENV_DENYLIST contains proxy env vars."""
    expected_vars = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
    assert expected_vars.issubset(SAFETY_PROXY_ENV_DENYLIST)
    assert isinstance(SAFETY_PROXY_ENV_DENYLIST, set)


def test_safety_env_allowlist():
    """Test that SAFETY_ENV_ALLOWLIST is a set."""
    assert isinstance(SAFETY_ENV_ALLOWLIST, set)


def test_default_timeout_values():
    """Test that default timeout values are positive floats."""
    assert DEFAULT_TIMEOUT > 0
    assert DEFAULT_TOOL_TIMEOUT > 0
    assert DEFAULT_MAX_TOOL_TIME > 0
    assert DEFAULT_MAX_TOTAL_FUZZING_TIME > 0
    assert DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT > 0
    assert DEFAULT_FORCE_KILL_TIMEOUT > 0
    assert all(
        isinstance(v, float)
        for v in [
            DEFAULT_TIMEOUT,
            DEFAULT_TOOL_TIMEOUT,
            DEFAULT_MAX_TOOL_TIME,
            DEFAULT_MAX_TOTAL_FUZZING_TIME,
            DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
            DEFAULT_FORCE_KILL_TIMEOUT,
        ]
    )


def test_default_run_counts():
    """Test that default run counts are positive integers."""
    assert DEFAULT_TOOL_RUNS > 0
    assert DEFAULT_PROTOCOL_RUNS_PER_TYPE > 0
    assert isinstance(DEFAULT_TOOL_RUNS, int)
    assert isinstance(DEFAULT_PROTOCOL_RUNS_PER_TYPE, int)


def test_default_protocol_version():
    """Test that default protocol version is a string."""
    assert isinstance(DEFAULT_PROTOCOL_VERSION, str)
    assert len(DEFAULT_PROTOCOL_VERSION) > 0
