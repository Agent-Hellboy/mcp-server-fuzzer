#!/usr/bin/env python3
"""
Unit tests for ToolClient.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.client.tool_client import ToolClient


@pytest.mark.asyncio
async def test_get_tools_from_server_records_schema_checks():
    mock_transport = MagicMock()
    client = ToolClient(
        mock_transport,
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client._rpc = MagicMock()
    client._rpc.get_tools = AsyncMock(
        return_value=[{"name": "alpha"}, {"name": "beta"}]
    )

    with patch(
        "mcp_fuzzer.spec_guard.check_tool_schema_fields",
        side_effect=[[{"status": "FAIL"}], []],
    ):
        tools = await client._get_tools_from_server()

    assert tools == [{"name": "alpha"}, {"name": "beta"}]
    assert "alpha" in client._tool_schema_checks
    assert "beta" not in client._tool_schema_checks


@pytest.mark.asyncio
async def test_fuzz_tool_safety_blocked():
    mock_transport = MagicMock()
    mock_safety = MagicMock()
    mock_safety.should_skip_tool_call.return_value = True
    client = ToolClient(
        mock_transport,
        auth_manager=MagicMock(),
        safety_system=mock_safety,
    )
    client._rpc = MagicMock()
    client._rpc.call_tool = AsyncMock()
    client.tool_mutator.mutate = AsyncMock(return_value={"x": 1})

    results = await client.fuzz_tool({"name": "alpha"}, runs=1)

    assert results[0]["safety_blocked"] is True
    assert results[0]["exception"] == "safety_blocked"
    client._rpc.call_tool.assert_not_called()


@pytest.mark.asyncio
async def test_fuzz_tool_success_with_auth_and_spec_checks():
    mock_transport = MagicMock()
    mock_safety = MagicMock()
    mock_safety.should_skip_tool_call.return_value = False
    mock_safety.sanitize_tool_arguments.return_value = {"x": "clean"}
    mock_auth = MagicMock()
    mock_auth.get_auth_params_for_tool.return_value = {"token": "abc"}
    client = ToolClient(
        mock_transport,
        auth_manager=mock_auth,
        safety_system=mock_safety,
    )
    client._rpc = MagicMock()
    client._rpc.call_tool = AsyncMock(return_value={"ok": True})
    client.tool_mutator.mutate = AsyncMock(return_value={"x": "dirty"})

    with patch(
        "mcp_fuzzer.spec_guard.check_tool_result_content",
        return_value=[{"id": "spec"}],
    ):
        results = await client.fuzz_tool({"name": "alpha"}, runs=1)

    result = results[0]
    assert result["args"] == {"x": "clean"}
    assert result["success"] is True
    assert result["spec_checks"] == [{"id": "spec"}]
    client._rpc.call_tool.assert_called_once_with(
        "alpha",
        {"x": "clean", "token": "abc"},
    )


@pytest.mark.asyncio
async def test_fuzz_all_tools_includes_schema_results():
    mock_transport = MagicMock()
    client = ToolClient(
        mock_transport,
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client._get_tools_from_server = AsyncMock(return_value=[{"name": "alpha"}])
    client._fuzz_single_tool_with_timeout = AsyncMock(
        return_value=[{"exception": "boom"}]
    )
    client._tool_schema_checks = {"alpha": [{"status": "FAIL"}]}

    results = await client.fuzz_all_tools(runs_per_tool=1)

    entry = results["alpha"]
    assert entry["runs"] == [{"exception": "boom"}]
    assert entry["spec_checks"] == [{"status": "FAIL"}]
    assert entry["spec_scope"] == "tool_schema"
    assert entry["spec_checks_passed"] is False


@pytest.mark.asyncio
async def test_fuzz_single_tool_with_timeout_returns_timeout_error():
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    tool = {"name": "alpha"}

    async def _fake_wait_for(task, timeout=None):
        raise asyncio.TimeoutError()

    with patch("mcp_fuzzer.client.tool_client.asyncio.wait_for", _fake_wait_for):
        results = await client._fuzz_single_tool_with_timeout(tool, runs_per_tool=1)

    assert results[0]["error"] == "tool_timeout"


@pytest.mark.asyncio
async def test_process_fuzz_results_safety_blocked():
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client.safety_system.should_skip_tool_call.return_value = True

    results = await client._process_fuzz_results("alpha", [{"args": {"x": 1}}])

    assert results[0]["exception"] == "safety_blocked"
    assert results[0]["safety_blocked"] is True


@pytest.mark.asyncio
async def test_process_fuzz_results_success_and_spec_checks():
    transport = MagicMock()
    safety = MagicMock()
    safety.should_skip_tool_call.return_value = False
    safety.sanitize_tool_arguments.return_value = {"x": 2}
    auth = MagicMock()
    auth.get_auth_params_for_tool.return_value = {"token": "abc"}
    client = ToolClient(transport, auth_manager=auth, safety_system=safety)
    client._rpc = MagicMock()
    client._rpc.call_tool = AsyncMock(return_value={"content": []})

    with patch(
        "mcp_fuzzer.spec_guard.check_tool_result_content",
        return_value=[{"id": "spec"}],
    ):
        results = await client._process_fuzz_results("alpha", [{"args": {"x": 1}}])

    assert results[0]["success"] is True
    assert results[0]["args"] == {"x": 2}
    assert results[0]["spec_checks"] == [{"id": "spec"}]
    client._rpc.call_tool.assert_called_once_with("alpha", {"x": 2, "token": "abc"})


@pytest.mark.asyncio
async def test_fuzz_tool_both_phases_runs():
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client.tool_mutator.mutate = AsyncMock(side_effect=[{"a": 1}, {"b": 2}])
    client._process_fuzz_results = AsyncMock(
        side_effect=[[{"ok": True}], [{"ok": False}]]
    )

    result = await client.fuzz_tool_both_phases({"name": "alpha"}, runs_per_phase=1)

    assert result["realistic"] == [{"ok": True}]
    assert result["aggressive"] == [{"ok": False}]
