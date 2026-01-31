#!/usr/bin/env python3
"""
Tests for security-focused helpers in ToolClient.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_fuzzer.auth.manager import AuthManager
from mcp_fuzzer.auth.providers import AuthProvider
from mcp_fuzzer.client.tool_client import ToolClient
from mcp_fuzzer.security_mode import build_security_policy

pytestmark = [pytest.mark.unit, pytest.mark.client]


class _TestAuthProvider(AuthProvider):
    """Simple provider that exposes both headers and params."""

    def get_auth_headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer valid-token"}

    def get_auth_params(self) -> dict[str, Any]:
        return {"token": "valid-token", "signature": "ok"}


class _DummyTransport:
    def __init__(self) -> None:
        self.auth_headers = {"Authorization": "Bearer valid-token"}
        self.session_id = "session-new"
        self.process = None


class _DummyRpc:
    def __init__(self):
        self.called: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        self.called.append((tool_name, args))
        return {"status": "ok"}

    async def get_tools(self) -> list[dict[str, Any]]:
        return []


@pytest.mark.asyncio
async def test_negative_auth_probe_yields_findings():
    auth_manager = AuthManager()
    auth_provider = _TestAuthProvider()
    auth_manager.add_auth_provider("probe", auth_provider)
    auth_manager.map_tool_to_auth("sample-tool", "probe")

    policy = build_security_policy({"security_mode": "full"})
    client = ToolClient(
        transport=_DummyTransport(),
        auth_manager=auth_manager,
        security_policy=policy,
    )
    client._rpc = _DummyRpc()

    sanitized_args = {"path": "/tmp/test"}
    findings = await client._run_negative_auth_probes(
        "sample-tool", sanitized_args, {"token": "valid-token"}
    )
    types = {finding["type"] for finding in findings}
    assert "missing_auth" in types
    assert "invalid_auth" in types


@pytest.mark.asyncio
async def test_session_replay_detection_records_violation():
    auth_manager = AuthManager()
    policy = build_security_policy({"security_mode": "full"})
    client = ToolClient(
        transport=_DummyTransport(),
        auth_manager=auth_manager,
        security_policy=policy,
    )
    client._rpc = _DummyRpc()
    client._last_session_id = "session-old"
    client.transport.session_id = "session-new"

    findings = await client._attempt_session_replay("sample-tool")
    assert findings
    assert findings[0]["type"] == "session_replay"
