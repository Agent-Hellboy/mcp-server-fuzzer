#!/usr/bin/env python3
"""
Unit tests for ProtocolExecutor.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import ProtocolExecutor
from mcp_fuzzer.fuzz_engine.mutators import ProtocolMutator, BatchMutator
from mcp_fuzzer.fuzz_engine.fuzzerreporter import ResultBuilder

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.executor]


@pytest.fixture
def mock_transport():
    """Fixture for mock transport."""
    transport = AsyncMock()
    transport.send_raw.return_value = {"jsonrpc": "2.0", "result": "ok"}
    transport.send_batch_request.return_value = [
        {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
    ]
    transport.collate_batch_responses.return_value = {
        1: {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
    }
    return transport


@pytest.fixture
def protocol_executor(mock_transport):
    """Fixture for ProtocolExecutor."""
    return ProtocolExecutor(transport=mock_transport)


@pytest.mark.asyncio
async def test_protocol_executor_init(protocol_executor):
    """Test ProtocolExecutor initialization."""
    assert protocol_executor.mutator is not None
    assert protocol_executor.batch_mutator is not None
    assert protocol_executor.executor is not None
    assert protocol_executor.result_builder is not None
    assert protocol_executor.transport is not None


@pytest.mark.asyncio
async def test_protocol_executor_init_with_custom_components():
    """Test ProtocolExecutor initialization with custom components."""
    mutator = ProtocolMutator()
    batch_mutator = BatchMutator()
    result_builder = ResultBuilder()
    executor = ProtocolExecutor(
        mutator=mutator,
        batch_mutator=batch_mutator,
        result_builder=result_builder,
    )
    assert executor.mutator is mutator
    assert executor.batch_mutator is batch_mutator
    assert executor.result_builder is result_builder


@pytest.mark.asyncio
async def test_execute_success(protocol_executor, mock_transport):
    """Test successful protocol execution."""
    results = await protocol_executor.execute("InitializeRequest", runs=3)
    assert len(results) == 3
    for result in results:
        assert result["protocol_type"] == "InitializeRequest"
        assert "fuzz_data" in result
        assert result["success"] is True


@pytest.mark.asyncio
async def test_execute_zero_runs(protocol_executor):
    """Test execution with zero runs."""
    results = await protocol_executor.execute("InitializeRequest", runs=0)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_negative_runs(protocol_executor):
    """Test execution with negative runs."""
    results = await protocol_executor.execute("InitializeRequest", runs=-1)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_unknown_protocol_type(protocol_executor):
    """Test execution with unknown protocol type."""
    results = await protocol_executor.execute("UnknownType", runs=3)
    assert len(results) == 0


@pytest.mark.asyncio
async def test_execute_generate_only(protocol_executor, mock_transport):
    """Test execution with generate_only=True."""
    results = await protocol_executor.execute(
        "InitializeRequest", runs=2, generate_only=True
    )
    assert len(results) == 2
    mock_transport.send_raw.assert_not_called()


@pytest.mark.asyncio
async def test_execute_transport_error(protocol_executor, mock_transport):
    """Test execution when transport raises an error."""
    mock_transport.send_raw.side_effect = Exception("Transport error")
    results = await protocol_executor.execute("InitializeRequest", runs=2)
    assert len(results) == 2
    for result in results:
        assert result["success"] is False
        assert "server_error" in result


@pytest.mark.asyncio
async def test_execute_both_phases(protocol_executor):
    """Test execution in both phases."""
    results = await protocol_executor.execute_both_phases(
        "InitializeRequest", runs_per_phase=2
    )
    assert "realistic" in results
    assert "aggressive" in results
    assert len(results["realistic"]) == 2
    assert len(results["aggressive"]) == 2


@pytest.mark.asyncio
async def test_execute_all_types(protocol_executor):
    """Test execution for all protocol types."""
    results = await protocol_executor.execute_all_types(runs_per_type=1)
    assert isinstance(results, dict)
    assert len(results) > 0
    for protocol_type, protocol_results in results.items():
        assert isinstance(protocol_results, list)


@pytest.mark.asyncio
async def test_execute_all_types_zero_runs(protocol_executor):
    """Test execution for all types with zero runs."""
    results = await protocol_executor.execute_all_types(runs_per_type=0)
    assert isinstance(results, dict)


@pytest.mark.asyncio
async def test_execute_with_invariant_violation(protocol_executor, mock_transport):
    """Test execution with invariant violation."""
    from mcp_fuzzer.fuzz_engine.executor.invariants import InvariantViolation

    with patch(
        "mcp_fuzzer.fuzz_engine.executor.protocol_executor.verify_response_invariants"
    ) as mock_verify:
        mock_verify.side_effect = InvariantViolation("Missing jsonrpc field")
        results = await protocol_executor.execute("InitializeRequest", runs=1)
        assert len(results) == 1
        assert "invariant_violations" in results[0]
        assert len(results[0]["invariant_violations"]) > 0


@pytest.mark.asyncio
async def test_execute_with_batch_response(protocol_executor, mock_transport):
    """Test execution with batch response."""
    mock_transport.send_raw.return_value = [
        {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
        {"jsonrpc": "2.0", "id": 2, "result": "ok2"},
    ]
    results = await protocol_executor.execute("InitializeRequest", runs=1)
    assert len(results) == 1


@pytest.mark.asyncio
async def test_execute_batch_validation_timeout(protocol_executor, mock_transport):
    """Test execution with batch validation timeout."""
    # Set up transport to return a dict without "jsonrpc" key
    # to trigger batch validation path
    mock_transport.send_raw.return_value = {
        1: {"id": 1, "result": "ok1"},
    }

    async def slow_verify(*args, **kwargs):
        await asyncio.sleep(10)
        return {}

    with patch(
        "mcp_fuzzer.fuzz_engine.executor.protocol_executor.verify_batch_responses",
        side_effect=slow_verify,
    ):
        results = await protocol_executor.execute("InitializeRequest", runs=1)
        assert len(results) == 1
        violations = results[0].get("invariant_violations", [])
        # Check that timeout violation was added
        assert any("timed out" in str(viol).lower() for viol in violations)


@pytest.mark.asyncio
async def test_execute_cancelled_error(protocol_executor):
    """Test execution with cancelled error."""
    with patch.object(
        protocol_executor.executor, "execute_batch", side_effect=asyncio.CancelledError
    ):
        with pytest.raises(asyncio.CancelledError):
            await protocol_executor.execute("InitializeRequest", runs=1)


@pytest.mark.asyncio
async def test_shutdown(protocol_executor):
    """Test executor shutdown."""
    # Mock the executor's shutdown method
    protocol_executor.executor.shutdown = AsyncMock()
    await protocol_executor.shutdown()
    protocol_executor.executor.shutdown.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("runs", [0, -1])
async def test_execute_returns_empty_for_non_positive_runs(runs):
    executor = ProtocolExecutor()
    assert await executor.execute("PingRequest", runs=runs) == []


@pytest.mark.asyncio
async def test_execute_returns_empty_for_missing_fuzzer_method(monkeypatch):
    executor = ProtocolExecutor()
    monkeypatch.setattr(
        executor.mutator,
        "get_fuzzer_method",
        lambda *_args, **_kwargs: None,
    )
    assert await executor.execute("PingRequest", runs=1) == []


@pytest.mark.asyncio
async def test_execute_and_process_operations_cancelled(monkeypatch):
    executor = ProtocolExecutor()
    executor.executor = MagicMock()
    executor.executor.execute_batch = AsyncMock(
        return_value={"results": [], "errors": [asyncio.CancelledError()]}
    )

    with pytest.raises(asyncio.CancelledError):
        await executor._execute_and_process_operations([], "PingRequest")


@pytest.mark.asyncio
async def test_execute_single_run_exception_path(monkeypatch):
    executor = ProtocolExecutor()
    monkeypatch.setattr(
        executor.mutator,
        "mutate",
        AsyncMock(side_effect=ValueError("boom")),
    )

    result = await executor._execute_single_run("PingRequest", 0, "realistic")

    assert result["success"] is False
    assert "boom" in result["exception"]


@pytest.mark.asyncio
async def test_send_fuzzed_request_batch_path():
    transport = MagicMock()
    transport.send_batch_request = AsyncMock(return_value=[{"id": 1, "result": "ok"}])
    transport.collate_batch_responses = MagicMock(return_value={1: {"result": "ok"}})
    executor = ProtocolExecutor(transport=transport)

    response, error = await executor._send_fuzzed_request(
        "BatchRequest", [{"id": 1, "method": "ping"}], generate_only=False
    )

    assert error is None
    assert response == {1: {"result": "ok"}}


@pytest.mark.asyncio
async def test_execute_all_types_timeout_branch(monkeypatch):
    executor = ProtocolExecutor()
    monkeypatch.setattr(executor, "PROTOCOL_TYPES", ("PingRequest",))
    monkeypatch.setattr(executor, "_execute_single_type", AsyncMock(return_value=[]))
    with patch(
        "mcp_fuzzer.fuzz_engine.executor.protocol_executor.asyncio.wait_for",
        AsyncMock(side_effect=asyncio.TimeoutError),
    ):
        result = await executor.execute_all_types(runs_per_type=1)

        assert result == {"PingRequest": []}


@pytest.mark.asyncio
async def test_execute_batch_requests_handles_empty_and_exception(monkeypatch):
    executor = ProtocolExecutor()
    executor.batch_mutator = MagicMock()
    executor.batch_mutator.mutate = AsyncMock(side_effect=[[], RuntimeError("boom")])

    executor.result_builder = MagicMock()
    executor.result_builder.build_batch_result = MagicMock(
        side_effect=lambda **kwargs: {"run": kwargs.get("run_index")}
    )

    results = await executor.execute_batch_requests(runs=2)

    assert results == [{"run": 1}]
