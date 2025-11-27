#!/usr/bin/env python3
"""
Updated tests for ToolFuzzer that align with the new safety architecture.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import ToolExecutor
from mcp_fuzzer.fuzz_engine.mutators import ToolMutator

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.fuzzer]


@pytest.fixture()
def safety_mock():
    mock = MagicMock()
    mock.should_skip_tool_call.return_value = False
    mock.sanitize_tool_arguments.side_effect = lambda tool, args: args
    mock.create_safe_mock_response.return_value = {"error": {"code": -1}}
    return mock


@pytest.fixture()
def fuzzer(safety_mock):
    # Create a mock mutator
    mock_mutator = MagicMock(spec=ToolMutator)
    mock_mutator.mutate = AsyncMock(return_value={"name": "example", "count": 1})
    tool_executor = ToolExecutor(
        mutator=mock_mutator, safety_system=safety_mock, enable_safety=True
    )
    return tool_executor


@pytest.mark.asyncio
async def test_fuzz_tool_runs_requested_times(fuzzer, safety_mock):
    tool = {"name": "sample", "inputSchema": {"properties": {}}}

    results = await fuzzer.execute(tool, runs=3)

    assert len(results) == 3
    assert fuzzer.mutator.mutate.await_count == 3
    safety_mock.sanitize_tool_arguments.assert_called()
    assert all(result["success"] for result in results)


@pytest.mark.asyncio
async def test_fuzz_tool_blocks_when_safety_requests(fuzzer, safety_mock):
    safety_mock.should_skip_tool_call.return_value = True
    tool = {"name": "blocked_tool", "inputSchema": {"properties": {}}}

    results = await fuzzer.execute(tool, runs=1)

    assert len(results) == 1
    assert results[0]["safety_blocked"] is True
    safety_mock.log_blocked_operation.assert_called_once()


@pytest.mark.asyncio
async def test_fuzz_tool_handles_strategy_exception(fuzzer):
    fuzzer.mutator.mutate.side_effect = Exception("boom")
    tool = {"name": "unstable", "inputSchema": {"properties": {}}}

    results = await fuzzer.execute(tool, runs=2)

    assert len(results) == 2
    assert all(result["success"] is False for result in results)
    assert all(result["exception"] == "boom" for result in results)


@pytest.mark.asyncio
async def test_fuzz_tools_invokes_each_tool(fuzzer):
    with patch.object(fuzzer, "execute", new_callable=AsyncMock) as mock_fuzz:
        mock_fuzz.return_value = [{"tool_name": "sample", "success": True}]
        tools = [{"name": "tool1"}, {"name": "tool2"}]

        results = await fuzzer.execute_multiple(tools, runs_per_tool=1)

        assert set(results.keys()) == {"tool1", "tool2"}
        assert mock_fuzz.await_count == 2


@pytest.mark.asyncio
async def test_fuzz_tool_both_phases(fuzzer):
    with patch.object(fuzzer, "execute", new_callable=AsyncMock) as mock_fuzz:
        mock_fuzz.return_value = [{"success": True}]
        tool = {"name": "complex"}

        results = await fuzzer.execute_both_phases(tool, runs_per_phase=1)

        assert set(results.keys()) == {"realistic", "aggressive"}
        assert mock_fuzz.await_count == 2
        mock_fuzz.assert_any_await(tool, runs=1, phase="realistic")
        mock_fuzz.assert_any_await(tool, runs=1, phase="aggressive")


@pytest.mark.asyncio
async def test_fuzz_tool_respects_sanitized_changes(fuzzer, safety_mock):
    def sanitizer(tool_name, args):
        args = dict(args)
        args["count"] = 99
        return args

    safety_mock.sanitize_tool_arguments.side_effect = sanitizer
    tool = {"name": "sanitized", "inputSchema": {"properties": {}}}

    results = await fuzzer.execute(tool, runs=1)

    assert results[0]["args"]["count"] == 99
    assert results[0]["safety_sanitized"] is True


@pytest.mark.asyncio
async def test_fuzz_tool_handles_transport_errors(fuzzer):
    async def generate_args(*_, **__):
        raise Exception("transport failure")

    fuzzer.mutator.mutate = AsyncMock(side_effect=generate_args)
    tool = {"name": "transport", "inputSchema": {"properties": {}}}

    results = await fuzzer.execute(tool, runs=1)

    assert results[0]["success"] is False
    assert results[0]["exception"] == "transport failure"
