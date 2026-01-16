#!/usr/bin/env python3
"""
Unit tests for BatchExecutor.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import BatchExecutor
from mcp_fuzzer.fuzz_engine.mutators import BatchMutator
from mcp_fuzzer.fuzz_engine.fuzzerreporter import ResultBuilder

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.executor]


@pytest.fixture
def mock_transport():
    """Fixture for mock transport."""
    transport = AsyncMock()
    transport.send_batch_request.return_value = [
        {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
        {"jsonrpc": "2.0", "id": 2, "result": "ok2"},
    ]
    transport.collate_batch_responses.return_value = {
        1: {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
        2: {"jsonrpc": "2.0", "id": 2, "result": "ok2"},
    }
    return transport


@pytest.fixture
def batch_executor(mock_transport):
    """Fixture for BatchExecutor."""
    executor = BatchExecutor(transport=mock_transport)
    executor.batch_mutator.mutate = AsyncMock(
        return_value=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            }
        ]
    )
    return executor


@pytest.mark.asyncio
async def test_batch_executor_init(batch_executor):
    """Test BatchExecutor initialization."""
    assert batch_executor.batch_mutator is not None
    assert batch_executor.executor is not None
    assert batch_executor.result_builder is not None
    assert batch_executor.transport is not None


@pytest.mark.asyncio
async def test_batch_executor_init_with_custom_components():
    """Test BatchExecutor initialization with custom components."""
    batch_mutator = BatchMutator()
    result_builder = ResultBuilder()
    executor = BatchExecutor(
        batch_mutator=batch_mutator,
        result_builder=result_builder,
    )
    assert executor.batch_mutator is batch_mutator
    assert executor.result_builder is result_builder


@pytest.mark.asyncio
async def test_execute_success(batch_executor, mock_transport):
    """Test successful batch execution."""
    results = await batch_executor.execute(runs=3)
    assert len(results) == 3
    for result in results:
        assert result["protocol_type"] == "BatchRequest"
        assert "fuzz_data" in result
        assert "batch_size" in result


@pytest.mark.asyncio
async def test_execute_with_protocol_types(batch_executor):
    """Test execution with specific protocol types."""
    protocol_types = ["InitializeRequest", "ListResourcesRequest"]
    results = await batch_executor.execute(protocol_types=protocol_types, runs=2)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_execute_zero_runs(batch_executor):
    """Test execution with zero runs."""
    results = await batch_executor.execute(runs=0)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_negative_runs(batch_executor):
    """Test execution with negative runs."""
    results = await batch_executor.execute(runs=-1)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_generate_only(batch_executor, mock_transport):
    """Test execution with generate_only=True."""
    results = await batch_executor.execute(runs=2, generate_only=True)
    assert len(results) == 2
    mock_transport.send_batch_request.assert_not_called()


@pytest.mark.asyncio
async def test_execute_transport_error(batch_executor, mock_transport):
    """Test execution when transport raises an error."""
    mock_transport.send_batch_request.side_effect = Exception("Transport error")
    results = await batch_executor.execute(runs=2)
    assert len(results) == 2
    for result in results:
        assert result["success"] is False
        assert "server_error" in result


@pytest.mark.asyncio
async def test_execute_empty_batch_request(batch_executor):
    """Test execution when batch mutator returns None."""
    with patch.object(batch_executor.batch_mutator, "mutate", return_value=None):
        results = await batch_executor.execute(runs=3)
        assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_exception_handling(batch_executor):
    """Test execution exception handling."""
    with patch.object(
        batch_executor.batch_mutator, "mutate", side_effect=Exception("Test error")
    ):
        results = await batch_executor.execute(runs=1)
        assert len(results) == 1
        assert results[0]["success"] is False
        assert results[0]["server_error"] == "Test error"
        assert results[0]["server_rejected_input"] is True


@pytest.mark.asyncio
async def test_execute_different_phases(batch_executor):
    """Test execution in different phases."""
    realistic_results = await batch_executor.execute(runs=2, phase="realistic")
    aggressive_results = await batch_executor.execute(runs=2, phase="aggressive")
    assert len(realistic_results) == 2
    assert len(aggressive_results) == 2


@pytest.mark.asyncio
async def test_shutdown(batch_executor):
    """Test executor shutdown."""
    # Mock the executor's shutdown method
    batch_executor.executor.shutdown = AsyncMock()
    await batch_executor.shutdown()
    batch_executor.executor.shutdown.assert_awaited_once()
