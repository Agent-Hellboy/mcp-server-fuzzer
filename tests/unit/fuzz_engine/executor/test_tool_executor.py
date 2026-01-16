#!/usr/bin/env python3
"""
Comprehensive unit tests for ToolExecutor.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import ToolExecutor, AsyncFuzzExecutor
from mcp_fuzzer.fuzz_engine.mutators import ToolMutator
from mcp_fuzzer.fuzz_engine.fuzzerreporter import ResultBuilder, ResultCollector

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.executor]


@pytest.fixture
def safety_mock():
    """Fixture for mock safety system."""
    mock = MagicMock()
    mock.should_skip_tool_call.return_value = False
    mock.sanitize_tool_arguments.side_effect = lambda tool, args: args
    mock.log_blocked_operation.return_value = None
    return mock


@pytest.fixture
def mock_mutator():
    """Fixture for mock tool mutator."""
    mutator = MagicMock(spec=ToolMutator)
    mutator.mutate = AsyncMock(return_value={"param": "value"})
    return mutator


@pytest.fixture
def tool_executor(safety_mock, mock_mutator):
    """Fixture for ToolExecutor."""
    return ToolExecutor(
        mutator=mock_mutator,
        safety_system=safety_mock,
        enable_safety=True,
    )


@pytest.mark.asyncio
async def test_tool_executor_init(tool_executor):
    """Test ToolExecutor initialization."""
    assert tool_executor.mutator is not None
    assert tool_executor.executor is not None
    assert tool_executor.result_builder is not None
    assert tool_executor.collector is not None
    assert tool_executor.safety_system is not None


@pytest.mark.asyncio
async def test_tool_executor_init_without_safety():
    """Test ToolExecutor initialization without safety."""
    executor = ToolExecutor(enable_safety=False)
    assert executor.safety_system is None


@pytest.mark.asyncio
async def test_tool_executor_init_with_custom_components():
    """Test ToolExecutor initialization with custom components."""
    mutator = ToolMutator()
    async_executor = AsyncFuzzExecutor()
    result_builder = ResultBuilder()
    executor = ToolExecutor(
        mutator=mutator,
        executor=async_executor,
        result_builder=result_builder,
    )
    assert executor.mutator is mutator
    assert executor.executor is async_executor
    assert executor.result_builder is result_builder


@pytest.mark.asyncio
async def test_execute_success(tool_executor, safety_mock):
    """Test successful tool execution."""
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=3)
    assert len(results) == 3
    assert all(result["success"] for result in results)
    assert all(result["tool_name"] == "test_tool" for result in results)


@pytest.mark.asyncio
async def test_execute_safety_blocked(tool_executor, safety_mock):
    """Test execution when safety blocks the operation."""
    safety_mock.should_skip_tool_call.return_value = True
    tool = {"name": "dangerous_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=1)
    assert len(results) == 1
    assert results[0]["safety_blocked"] is True
    assert results[0]["success"] is False
    safety_mock.log_blocked_operation.assert_called()


@pytest.mark.asyncio
async def test_execute_safety_sanitized(tool_executor, safety_mock):
    """Test execution with sanitized arguments."""

    def sanitize(tool_name, args):
        return {"sanitized": True}

    safety_mock.sanitize_tool_arguments.side_effect = sanitize
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=1)
    assert results[0]["safety_sanitized"] is True
    assert results[0]["args"] == {"sanitized": True}


@pytest.mark.asyncio
async def test_execute_mutator_exception(tool_executor):
    """Test execution when mutator raises an exception."""
    tool_executor.mutator.mutate.side_effect = Exception("Mutator error")
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=1)
    assert len(results) == 1
    assert results[0]["success"] is False
    assert "Mutator error" in results[0]["exception"]


@pytest.mark.asyncio
async def test_execute_executor_error(tool_executor):
    """Test execution when executor raises an error."""
    tool_executor.executor.execute_batch = AsyncMock(
        return_value={"results": [], "errors": [ValueError("Executor error")]}
    )
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=1)
    assert len(results) == 1
    assert all(result["success"] is False for result in results)
    assert all("Executor error" in result["exception"] for result in results)


@pytest.mark.asyncio
async def test_execute_both_phases(tool_executor):
    """Test execution in both phases."""
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute_both_phases(tool, runs_per_phase=2)
    assert "realistic" in results
    assert "aggressive" in results
    assert len(results["realistic"]) == 2
    assert len(results["aggressive"]) == 2


@pytest.mark.asyncio
async def test_execute_multiple_tools(tool_executor):
    """Test execution for multiple tools."""
    tools = [
        {"name": "tool1", "inputSchema": {"properties": {}}},
        {"name": "tool2", "inputSchema": {"properties": {}}},
    ]
    results = await tool_executor.execute_multiple(tools, runs_per_tool=2)
    assert "tool1" in results
    assert "tool2" in results
    assert len(results["tool1"]) == 2
    assert len(results["tool2"]) == 2


@pytest.mark.asyncio
async def test_execute_multiple_tools_none(tool_executor):
    """Test execution for None tools list."""
    results = await tool_executor.execute_multiple(None, runs_per_tool=1)
    assert results == {}


@pytest.mark.asyncio
async def test_execute_multiple_tools_exception(tool_executor):
    """Test execution when one tool raises an exception."""
    tool_executor._execute_single_tool = AsyncMock(
        side_effect=[Exception("Tool error"), [{"success": True}]]
    )
    tools = [
        {"name": "tool1", "inputSchema": {"properties": {}}},
        {"name": "tool2", "inputSchema": {"properties": {}}},
    ]
    results = await tool_executor.execute_multiple(tools, runs_per_tool=1)
    assert "tool1" in results
    assert "tool2" in results


@pytest.mark.asyncio
async def test_execute_different_phases(tool_executor):
    """Test execution in different phases."""
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    realistic_results = await tool_executor.execute(tool, runs=2, phase="realistic")
    aggressive_results = await tool_executor.execute(tool, runs=2, phase="aggressive")
    assert len(realistic_results) == 2
    assert len(aggressive_results) == 2


@pytest.mark.asyncio
async def test_execute_with_original_args(tool_executor, safety_mock):
    """Test execution preserves original args when sanitized."""

    def sanitize(tool_name, args):
        return {"sanitized": True}

    safety_mock.sanitize_tool_arguments.side_effect = sanitize
    tool = {"name": "test_tool", "inputSchema": {"properties": {}}}
    results = await tool_executor.execute(tool, runs=1)
    assert "original_args" in results[0]
    assert results[0]["original_args"] == {"param": "value"}


@pytest.mark.asyncio
async def test_shutdown(tool_executor):
    """Test executor shutdown."""
    # Mock the executor's shutdown method
    tool_executor.executor.shutdown = AsyncMock()
    await tool_executor.shutdown()
    tool_executor.executor.shutdown.assert_awaited_once()
