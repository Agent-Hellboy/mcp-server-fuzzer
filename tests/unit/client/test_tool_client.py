#!/usr/bin/env python3
"""
Unit tests for ToolClient.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.client.tool_client import ToolClient


def _make_client():
    """Build a ToolClient with permissive safety (no skip, identity sanitize)."""
    safety = MagicMock()
    safety.should_skip_tool_call.return_value = False
    safety.sanitize_tool_arguments.side_effect = lambda _name, args: args
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=safety,
    )
    client.auth_manager.get_auth_params_for_tool.return_value = {}
    client._rpc = MagicMock()
    return client, safety


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
    assert results[0]["error"] == "safety_blocked"
    assert "exception" not in results[0]
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
    assert result["success"] is False
    assert result.get("accepted_malformed") is True
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

    with patch(
        "mcp_fuzzer.client.tool_client_fuzzing.asyncio.wait_for", _fake_wait_for
    ):
        results = await client._fuzz_single_tool_with_timeout(tool, runs_per_tool=1)

    assert results[0]["error"] == "tool_timeout"
    assert results[0]["timeout_scope"] == "session"


@pytest.mark.asyncio
async def test_process_fuzz_results_safety_blocked():
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client.safety_system.should_skip_tool_call.return_value = True

    results = await client._process_fuzz_results("alpha", [{"args": {"x": 1}}])

    assert results[0]["error"] == "safety_blocked"
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

    assert results[0]["success"] is False
    assert results[0].get("accepted_malformed") is True
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
    client._execute_tool_call = AsyncMock(
        side_effect=[{"ok": True}, {"ok": False}]
    )

    result = await client.fuzz_tool_both_phases({"name": "alpha"}, runs_per_phase=1)

    assert result["realistic"] == [{"ok": True}]
    assert result["aggressive"] == [{"ok": False}]


@pytest.mark.asyncio
async def test_fuzz_tool_both_phases_forwards_tool_timeout():
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=MagicMock(),
    )
    client.tool_mutator.mutate = AsyncMock(side_effect=[{"a": 1}, {"b": 2}])
    client._execute_tool_call = AsyncMock(
        side_effect=[{"ok": True}, {"ok": False}]
    )

    await client.fuzz_tool_both_phases(
        {"name": "alpha"},
        runs_per_phase=1,
        tool_timeout=0.25,
    )

    first_timeout = client._execute_tool_call.await_args_list[0].kwargs[
        "tool_timeout"
    ]
    second_timeout = client._execute_tool_call.await_args_list[1].kwargs[
        "tool_timeout"
    ]
    assert first_timeout == 0.25
    assert second_timeout == 0.25


@pytest.mark.asyncio
async def test_fuzz_tool_applies_per_call_timeout():
    safety = MagicMock()
    safety.should_skip_tool_call.return_value = False
    safety.sanitize_tool_arguments.side_effect = lambda _name, args: args
    client = ToolClient(
        MagicMock(),
        auth_manager=MagicMock(),
        safety_system=safety,
    )
    client.tool_mutator.mutate = AsyncMock(return_value={"x": 1})

    async def _slow_call(*_args, **_kwargs):
        await asyncio.sleep(0.05)
        return {"ok": True}

    client._rpc = MagicMock()
    client._rpc.call_tool = _slow_call

    results = await client.fuzz_tool(
        {"name": "alpha"},
        runs=1,
        tool_timeout=0.01,
    )

    assert results[0]["success"] is False
    assert results[0]["error"] == "tool_timeout"
    assert results[0]["timeout_scope"] == "call"
    assert "timed out" in results[0]["exception"]


@pytest.mark.asyncio
async def test_get_tools_empty_list():
    client, _ = _make_client()
    client._rpc.get_tools = AsyncMock(return_value=[])

    result = await client._get_tools_from_server()
    assert result == []


@pytest.mark.asyncio
async def test_get_tools_exception():
    client, _ = _make_client()
    client._rpc.get_tools = AsyncMock(side_effect=Exception("connection failed"))

    result = await client._get_tools_from_server()
    assert result == []


@pytest.mark.asyncio
async def test_fuzz_tool_safety_sanitized():
    client, safety = _make_client()
    safety.sanitize_tool_arguments.side_effect = None
    safety.sanitize_tool_arguments.return_value = {"cmd": "safe_value"}

    tool = {"name": "test_tool"}
    client.tool_mutator.mutate = AsyncMock(return_value={"cmd": "dangerous_value"})
    client._rpc.call_tool = AsyncMock(return_value={"content": []})

    results = await client.fuzz_tool(tool, runs=1)

    assert len(results) == 1
    assert results[0]["safety_sanitized"] is True


@pytest.mark.asyncio
async def test_fuzz_tool_call_exception():
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.tool_mutator.mutate = AsyncMock(return_value={})
    client._rpc.call_tool = AsyncMock(side_effect=Exception("call failed"))

    results = await client.fuzz_tool(tool, runs=1)

    assert len(results) == 1
    assert results[0]["success"] is False
    assert "call failed" in results[0]["exception"]


@pytest.mark.asyncio
async def test_fuzz_tool_mutator_exception():
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.tool_mutator.mutate = AsyncMock(side_effect=Exception("mutator failed"))

    results = await client.fuzz_tool(tool, runs=1)

    assert len(results) == 1
    assert results[0]["success"] is False
    assert "mutator failed" in results[0]["exception"]


@pytest.mark.asyncio
async def test_fuzz_all_tools_empty():
    client, _ = _make_client()
    client._get_tools_from_server = AsyncMock(return_value=[])

    results = await client.fuzz_all_tools()
    assert results == {}


@pytest.mark.asyncio
async def test_fuzz_all_tools_timeout_protection():
    client, _ = _make_client()
    client._get_tools_from_server = AsyncMock(return_value=[{"name": "tool1"}])

    # Simulate slow fuzzing (0.1s does not trip the early-stop branch)
    async def slow_fuzz(*args, **kwargs):
        await asyncio.sleep(0.1)
        return [{"success": True}]

    client._fuzz_single_tool_with_timeout = slow_fuzz

    # This should complete without hanging
    results = await client.fuzz_all_tools(runs_per_tool=1)
    assert "tool1" in results


@pytest.mark.asyncio
async def test_fuzz_with_timeout_exception():
    client, _ = _make_client()
    tool = {"name": "failing_tool"}
    client.fuzz_tool = AsyncMock(side_effect=Exception("unexpected error"))

    results = await client._fuzz_single_tool_with_timeout(tool, 1)

    assert len(results) == 1
    assert results[0]["error"] == "phase_execution_failed"
    assert "unexpected error" in results[0]["exception"]


@pytest.mark.asyncio
async def test_both_phases_exception():
    """A per-run mutator error becomes a per-run failure entry, not a
    phase abort."""
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.tool_mutator.mutate = AsyncMock(side_effect=Exception("mutator error"))

    results = await client.fuzz_tool_both_phases(tool, runs_per_phase=1)

    assert set(results) == {"realistic", "aggressive"}
    for phase in ("realistic", "aggressive"):
        assert len(results[phase]) == 1
        run = results[phase][0]
        assert run["error"] == "phase_execution_failed"
        assert "mutator error" in run["exception"]


@pytest.mark.asyncio
async def test_process_results_call_exception():
    client, _ = _make_client()
    client._rpc.call_tool = AsyncMock(side_effect=Exception("call failed"))

    fuzz_results = [{"args": {}}]

    results = await client._process_fuzz_results("test_tool", fuzz_results)

    assert len(results) == 1
    assert results[0]["success"] is False
    assert "call failed" in results[0]["exception"]


@pytest.mark.asyncio
async def test_fuzz_all_both_phases_success():
    client, _ = _make_client()
    client._get_tools_from_server = AsyncMock(return_value=[{"name": "tool1"}])
    client._fuzz_single_tool_both_phases = AsyncMock(
        return_value={"realistic": [], "aggressive": []}
    )

    results = await client.fuzz_all_tools_both_phases(runs_per_phase=1)

    assert "tool1" in results


@pytest.mark.asyncio
async def test_fuzz_all_both_phases_no_tools():
    client, _ = _make_client()
    client._get_tools_from_server = AsyncMock(return_value=[])

    results = await client.fuzz_all_tools_both_phases()

    assert results == {}


@pytest.mark.asyncio
async def test_fuzz_all_both_phases_exception():
    client, _ = _make_client()
    client._get_tools_from_server = AsyncMock(side_effect=Exception("error"))

    results = await client.fuzz_all_tools_both_phases()

    assert results == {}


@pytest.mark.asyncio
async def test_single_tool_both_phases_success():
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.fuzz_tool_both_phases = AsyncMock(
        return_value={"realistic": [], "aggressive": []}
    )

    result = await client._fuzz_single_tool_both_phases(tool, 2)

    assert "realistic" in result
    assert "aggressive" in result


@pytest.mark.asyncio
async def test_single_tool_both_phases_error_result():
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.fuzz_tool_both_phases = AsyncMock(return_value={"error": "some error"})

    result = await client._fuzz_single_tool_both_phases(tool, 2)

    assert "error" in result
    assert result["error"] == "some error"


@pytest.mark.asyncio
async def test_single_tool_both_phases_exception():
    client, _ = _make_client()
    tool = {"name": "test_tool"}
    client.fuzz_tool_both_phases = AsyncMock(side_effect=Exception("boom"))

    result = await client._fuzz_single_tool_both_phases(tool, 2)

    assert "error" in result
    assert "boom" in result["error"]
    assert result["runs"][0]["exception"] == "boom"


@pytest.mark.asyncio
async def test_fuzz_tool_with_safety_disabled():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": "ok"})
    client = ToolClient(
        transport=transport,
        safety_system=None,
        enable_safety=False,
    )

    tool = {"name": "test_tool"}
    client.tool_mutator.mutate = AsyncMock(return_value={})
    client._rpc.call_tool = AsyncMock(return_value={"content": []})

    results = await client.fuzz_tool(tool, runs=1)

    assert len(results) == 1
    assert results[0]["safety_blocked"] is False
    assert results[0]["safety_sanitized"] is False


def test_print_phase_report_no_reporter():
    client, _ = _make_client()
    # Should not raise
    client._print_phase_report("test_tool", "realistic", [])


def test_print_phase_report_with_reporter():
    client, _ = _make_client()
    from mcp_fuzzer.reports import FuzzerReporter

    mock_reporter = MagicMock(spec=FuzzerReporter)
    mock_reporter.console = MagicMock()
    client.reporter = mock_reporter

    results = [{"success": True}, {"success": False}]
    client._print_phase_report("test_tool", "realistic", results)

    mock_reporter.console.print.assert_called()


@pytest.mark.asyncio
async def test_shutdown():
    client, _ = _make_client()
    await client.shutdown()
    # Should complete without error
