#!/usr/bin/env python3
"""
Enhanced unit tests for AsyncFuzzExecutor.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.executor]


@pytest.fixture
def executor():
    """Fixture for AsyncFuzzExecutor test cases."""
    return AsyncFuzzExecutor(max_concurrency=3)


@pytest.mark.asyncio
async def test_init():
    """Test AsyncFuzzExecutor initialization."""
    executor = AsyncFuzzExecutor(max_concurrency=5)
    assert executor.max_concurrency == 5
    assert executor._semaphore is None
    assert executor._thread_pool is not None


@pytest.mark.asyncio
async def test_get_semaphore_lazy_initialization(executor):
    """Test that semaphore is created lazily."""
    assert executor._semaphore is None
    sem = executor._get_semaphore()
    assert executor._semaphore is not None
    assert sem is executor._semaphore


@pytest.mark.asyncio
async def test_execute_batch_success(executor):
    """Test successful batch execution."""

    async def test_op(value):
        return value * 2

    operations = [(test_op, [5], {})]
    results = await executor.execute_batch(operations)
    assert results["results"][0] == 10
    assert len(results["errors"]) == 0


@pytest.mark.asyncio
async def test_execute_batch_sync_and_kwargs(executor):
    """Sync function with kwargs should work."""

    def add(x, *, y=0):
        return x + y

    operations = [(add, [2], {"y": 3})]
    results = await executor.execute_batch(operations)
    assert results["results"][0] == 5


@pytest.mark.asyncio
async def test_execute_batch_exception(executor):
    """Test exception handling during batch execution."""

    async def failing_op():
        raise ValueError("Test error")

    operations = [(failing_op, [], {})]
    results = await executor.execute_batch(operations)
    assert "errors" in results
    assert len(results["errors"]) == 1
    assert "Test error" in str(results["errors"][0])


@pytest.mark.asyncio
async def test_execute_batch_cancelled_error(executor):
    """Test that CancelledError is re-raised."""

    async def cancelled_op():
        raise asyncio.CancelledError

    operations = [(cancelled_op, [], {})]
    with pytest.raises(asyncio.CancelledError):
        await executor.execute_batch(operations)


@pytest.mark.asyncio
async def test_execute_batch_multiple_operations(executor):
    """Test batch execution with multiple operations."""

    async def op1():
        return "result1"

    async def op2():
        return "result2"

    operations = [(op1, [], {}), (op2, [], {})]
    results = await executor.execute_batch(operations)
    assert len(results["results"]) == 2
    assert "result1" in results["results"]
    assert "result2" in results["results"]


@pytest.mark.asyncio
async def test_execute_batch_mixed_success_and_errors(executor):
    """Test batch execution with mixed success and errors."""

    async def success_op():
        return "success"

    async def failing_op():
        raise ValueError("error")

    operations = [(success_op, [], {}), (failing_op, [], {})]
    results = await executor.execute_batch(operations)
    assert len(results["results"]) == 1
    assert len(results["errors"]) == 1
    assert results["results"][0] == "success"


@pytest.mark.asyncio
async def test_execute_batch_concurrency_limit(executor):
    """Test that concurrency is limited."""
    call_count = 0
    max_concurrent = 0
    semaphore = asyncio.Semaphore(1)

    async def concurrent_op():
        nonlocal call_count, max_concurrent
        async with semaphore:
            call_count += 1
            current = call_count
            await asyncio.sleep(0.01)
            max_concurrent = max(max_concurrent, current)
            call_count -= 1
        return current

    operations = [(concurrent_op, [], {}) for _ in range(5)]
    results = await executor.execute_batch(operations)
    assert len(results["results"]) == 5
    assert max_concurrent <= executor.max_concurrency


@pytest.mark.asyncio
async def test_run_hypothesis_strategy(executor):
    """Test Hypothesis strategy execution."""
    import hypothesis.strategies as st

    strategy = st.just("test_value")
    result = await executor.run_hypothesis_strategy(strategy)
    assert result == "test_value"


@pytest.mark.asyncio
async def test_run_hypothesis_strategy_complex(executor):
    """Test Hypothesis strategy with complex data."""
    import hypothesis.strategies as st

    strategy = st.dictionaries(st.text(), st.integers(), min_size=1, max_size=3)
    result = await executor.run_hypothesis_strategy(strategy)
    assert isinstance(result, dict)
    assert len(result) > 0


@pytest.mark.asyncio
async def test_shutdown(executor):
    """Test executor shutdown."""
    await executor.shutdown()
    assert executor._thread_pool._shutdown


@pytest.mark.asyncio
async def test_execute_single_async_function(executor):
    """Test executing a single async function."""

    async def async_func(x, y):
        return x + y

    result = await executor._execute_single(async_func, [1, 2], {})
    assert result == 3


@pytest.mark.asyncio
async def test_execute_single_sync_function(executor):
    """Test executing a single sync function."""

    def sync_func(x, y):
        return x * y

    result = await executor._execute_single(sync_func, [3, 4], {})
    assert result == 12


@pytest.mark.asyncio
async def test_execute_single_with_kwargs(executor):
    """Test executing a function with kwargs."""

    def func(x, *, multiplier=1):
        return x * multiplier

    result = await executor._execute_single(func, [5], {"multiplier": 3})
    assert result == 15


@pytest.mark.asyncio
async def test_execute_single_exception(executor):
    """Test exception handling in _execute_single."""

    async def failing_func():
        raise RuntimeError("Test error")

    with pytest.raises(RuntimeError, match="Test error"):
        await executor._execute_single(failing_func, [], {})


@pytest.mark.asyncio
async def test_execute_batch_empty_operations(executor):
    """Test batch execution with empty operations list."""
    results = await executor.execute_batch([])
    assert len(results["results"]) == 0
    assert len(results["errors"]) == 0
