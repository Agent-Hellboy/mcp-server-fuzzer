#!/usr/bin/env python3
"""
Unit tests for AsyncFuzzExecutor
"""

import asyncio
import pytest
from unittest.mock import AsyncMock

from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor


@pytest.fixture
def executor():
    """Fixture for AsyncFuzzExecutor test cases."""
    return AsyncFuzzExecutor(max_concurrency=3)


@pytest.mark.asyncio
async def test_init():
    """Test AsyncFuzzExecutor initialization."""
    executor = AsyncFuzzExecutor(max_concurrency=5)
    assert executor.max_concurrency == 5
    assert executor._semaphore._value == 5


@pytest.mark.asyncio
async def test_execute_batch_success(executor):
    """Test successful batch execution."""

    async def test_op(value):
        return value * 2

    operations = [(test_op, [5], {})]
    results = await executor.execute_batch(operations)
    assert results["results"][0] == 10


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
async def test_run_hypothesis_strategy(executor):
    """Test Hypothesis strategy execution."""
    import hypothesis.strategies as st

    # Test with a simple strategy
    strategy = st.just("test_value")
    result = await executor.run_hypothesis_strategy(strategy)
    assert result == "test_value"


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
async def test_shutdown(executor):
    """Test executor shutdown."""
    await executor.shutdown()
    # Shutdown should complete without error
