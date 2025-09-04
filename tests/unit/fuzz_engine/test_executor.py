#!/usr/bin/env python3
"""
Unit tests for AsyncFuzzExecutor
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine]


@pytest.fixture
def executor():
    """Fixture for AsyncFuzzExecutor test cases."""
    return AsyncFuzzExecutor(max_concurrency=3)


@pytest.mark.asyncio
async def test_init():
    """Test AsyncFuzzExecutor initialization."""
    executor = AsyncFuzzExecutor(
        max_concurrency=5,
        timeout=10.0,
        retry_count=2,
        retry_delay=0.5,
    )
    assert executor._max_concurrency == 5
    assert executor._timeout == 10.0
    assert executor._retry_count == 2
    assert executor._retry_delay == 0.5
    assert executor._semaphore._value == 5
    assert len(executor._running_tasks) == 0


@pytest.mark.asyncio
async def test_execute_success(executor):
    """Test successful execution of an operation."""

    async def test_op(value):
        return value * 2

    result = await executor.execute(test_op, 5)
    assert result == 10


@pytest.mark.asyncio
async def test_execute_timeout(executor):
    """Test timeout handling during execution."""

    async def slow_op():
        await asyncio.sleep(0.5)
        return "Done"

    with pytest.raises(asyncio.TimeoutError):
        await executor.execute(slow_op, timeout=0.1)


@pytest.mark.asyncio
async def test_execute_exception(executor):
    """Test exception handling during execution."""

    async def failing_op():
        raise ValueError("Test error")

    with pytest.raises(ValueError):
        await executor.execute(failing_op)


@pytest.mark.asyncio
async def test_execute_with_retry_success_first_try(executor):
    """Test retry mechanism with success on first try."""
    mock_op = AsyncMock(return_value="Success")

    result = await executor.execute_with_retry(mock_op)

    assert result == "Success"
    mock_op.assert_called_once()


@pytest.mark.asyncio
async def test_execute_with_retry_success_after_retry(executor):
    """Test retry mechanism with success after failures."""
    mock_op = AsyncMock(side_effect=[ValueError("Error 1"), "Success"])

    result = await executor.execute_with_retry(mock_op, retry_count=1, retry_delay=0.1)

    assert result == "Success"
    assert mock_op.call_count == 2


@pytest.mark.asyncio
async def test_execute_with_retry_all_failures(executor):
    """Test retry mechanism with all attempts failing."""
    mock_op = AsyncMock(
        side_effect=[
            ValueError("Error 1"),
            ValueError("Error 2"),
            ValueError("Error 3"),
        ]
    )

    with pytest.raises(ValueError):
        await executor.execute_with_retry(mock_op, retry_count=2, retry_delay=0.1)

    assert mock_op.call_count == 3  # Initial + 2 retries


@pytest.mark.asyncio
async def test_execute_batch_all_success(executor):
    """Test batch execution with all operations succeeding."""

    async def op1(x):
        return x * 2

    async def op2(x):
        return x + 10

    operations = [(op1, [5], {}), (op2, [7], {})]

    results = await executor.execute_batch(operations)

    assert len(results["results"]) == 2
    assert sorted(results["results"]) == [10, 17]
    assert len(results["errors"]) == 0


@pytest.mark.asyncio
async def test_execute_batch_mixed_results(executor):
    """Test batch execution with mixed successes and failures."""

    async def success_op(x):
        return x * 2

    async def fail_op(x):
        raise ValueError(f"Error with {x}")

    operations = [(success_op, [5], {}), (fail_op, [7], {}), (success_op, [10], {})]

    results = await executor.execute_batch(operations)

    assert len(results["results"]) == 2
    assert 10 in results["results"]
    assert 20 in results["results"]

    assert len(results["errors"]) == 1
    assert isinstance(results["errors"][0], ValueError)
    assert str(results["errors"][0]) == "Error with 7"


@pytest.mark.asyncio
async def test_execute_batch_no_collect(executor):
    """Test batch execution with collection disabled."""

    async def success_op(x):
        return x * 2

    async def fail_op(x):
        raise ValueError(f"Error with {x}")

    operations = [(success_op, [5], {}), (fail_op, [7], {}), (success_op, [10], {})]

    results = await executor.execute_batch(
        operations, collect_results=False, collect_errors=False
    )

    assert len(results["results"]) == 0
    assert len(results["errors"]) == 0


@pytest.mark.asyncio
async def test_concurrency_control():
    """Test that concurrency is properly controlled by checking semaphore value."""
    # Create a mock semaphore to track its usage
    mock_semaphore = MagicMock(spec=asyncio.Semaphore)
    mock_semaphore.__aenter__ = AsyncMock()
    mock_semaphore.__aexit__ = AsyncMock()
    mock_semaphore._value = 2  # Initial value

    # Create executor with the mock semaphore
    executor = AsyncFuzzExecutor(max_concurrency=2)
    executor._semaphore = mock_semaphore

    # Create a simple async operation
    async def test_op():
        return "test"

    # Execute a single operation
    await executor.execute(test_op)

    # Verify the semaphore's __aenter__ was called
    mock_semaphore.__aenter__.assert_called_once()
    # Verify the semaphore's __aexit__ was called
    mock_semaphore.__aexit__.assert_called_once()


@pytest.mark.asyncio
async def test_shutdown_no_tasks(executor):
    """Test shutdown with no running tasks."""
    await executor.shutdown()
    assert len(executor._running_tasks) == 0


@pytest.mark.asyncio
async def test_shutdown_with_tasks(executor):
    """Test shutdown with running tasks."""

    # Create some tasks
    async def long_task():
        try:
            await asyncio.sleep(10)
            return "Done"
        except asyncio.CancelledError:
            return "Cancelled"

    task1 = asyncio.create_task(executor._execute_and_track(long_task, [], {}))
    task2 = asyncio.create_task(executor._execute_and_track(long_task, [], {}))

    executor._running_tasks.add(task1)
    executor._running_tasks.add(task2)

    # Shutdown with short timeout
    await executor.shutdown(timeout=0.1)

    # Tasks should be cancelled
    assert task1.cancelled() or task1.done()
    assert task2.cancelled() or task2.done()

    # Running tasks set should be empty or contain only completed tasks
    for task in executor._running_tasks:
        assert task.done()
