#!/usr/bin/env python3
"""
Unit tests for AsyncFuzzExecutor
"""

import asyncio
import unittest
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor


class TestAsyncFuzzExecutor(unittest.TestCase):
    """Test cases for AsyncFuzzExecutor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.executor = AsyncFuzzExecutor(max_concurrency=3)

    @pytest.mark.asyncio
    async def test_init(self):
        """Test AsyncFuzzExecutor initialization."""
        executor = AsyncFuzzExecutor(
            max_concurrency=5,
            timeout=10.0,
            retry_count=2,
            retry_delay=0.5,
        )
        self.assertEqual(executor._max_concurrency, 5)
        self.assertEqual(executor._timeout, 10.0)
        self.assertEqual(executor._retry_count, 2)
        self.assertEqual(executor._retry_delay, 0.5)
        self.assertEqual(executor._semaphore._value, 5)
        self.assertEqual(len(executor._running_tasks), 0)

    @pytest.mark.asyncio
    async def test_execute_success(self):
        """Test successful execution of an operation."""
        async def test_op(value):
            return value * 2

        result = await self.executor.execute(test_op, 5)
        self.assertEqual(result, 10)

    @pytest.mark.asyncio
    async def test_execute_timeout(self):
        """Test timeout handling during execution."""
        async def slow_op():
            await asyncio.sleep(0.5)
            return "Done"

        with self.assertRaises(asyncio.TimeoutError):
            await self.executor.execute(slow_op, timeout=0.1)

    @pytest.mark.asyncio
    async def test_execute_exception(self):
        """Test exception handling during execution."""
        async def failing_op():
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            await self.executor.execute(failing_op)

    @pytest.mark.asyncio
    async def test_execute_with_retry_success_first_try(self):
        """Test retry mechanism with success on first try."""
        mock_op = AsyncMock(return_value="Success")

        result = await self.executor.execute_with_retry(mock_op)
        
        self.assertEqual(result, "Success")
        mock_op.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_with_retry_success_after_retry(self):
        """Test retry mechanism with success after failures."""
        mock_op = AsyncMock(side_effect=[ValueError("Error 1"), "Success"])

        result = await self.executor.execute_with_retry(
            mock_op, retry_count=1, retry_delay=0.1
        )
        
        self.assertEqual(result, "Success")
        self.assertEqual(mock_op.call_count, 2)

    @pytest.mark.asyncio
    async def test_execute_with_retry_all_failures(self):
        """Test retry mechanism with all attempts failing."""
        mock_op = AsyncMock(side_effect=[
            ValueError("Error 1"),
            ValueError("Error 2"),
            ValueError("Error 3")
        ])

        with self.assertRaises(ValueError):
            await self.executor.execute_with_retry(
                mock_op, retry_count=2, retry_delay=0.1
            )
        
        self.assertEqual(mock_op.call_count, 3)  # Initial + 2 retries

    @pytest.mark.asyncio
    async def test_execute_batch_all_success(self):
        """Test batch execution with all operations succeeding."""
        async def op1(x):
            return x * 2
            
        async def op2(x):
            return x + 10
            
        operations = [
            (op1, [5], {}),
            (op2, [7], {})
        ]
        
        results = await self.executor.execute_batch(operations)
        
        self.assertEqual(len(results["results"]), 2)
        self.assertCountEqual(results["results"], [10, 17])
        self.assertEqual(len(results["errors"]), 0)

    @pytest.mark.asyncio
    async def test_execute_batch_mixed_results(self):
        """Test batch execution with mixed successes and failures."""
        async def success_op(x):
            return x * 2
            
        async def fail_op(x):
            raise ValueError(f"Error with {x}")
            
        operations = [
            (success_op, [5], {}),
            (fail_op, [7], {}),
            (success_op, [10], {})
        ]
        
        results = await self.executor.execute_batch(operations)
        
        self.assertEqual(len(results["results"]), 2)
        self.assertIn(10, results["results"])
        self.assertIn(20, results["results"])
        
        self.assertEqual(len(results["errors"]), 1)
        self.assertIsInstance(results["errors"][0], ValueError)
        self.assertEqual(str(results["errors"][0]), "Error with 7")

    @pytest.mark.asyncio
    async def test_execute_batch_no_collect(self):
        """Test batch execution with collection disabled."""
        async def success_op(x):
            return x * 2
            
        async def fail_op(x):
            raise ValueError(f"Error with {x}")
            
        operations = [
            (success_op, [5], {}),
            (fail_op, [7], {}),
            (success_op, [10], {})
        ]
        
        results = await self.executor.execute_batch(
            operations, collect_results=False, collect_errors=False
        )
        
        self.assertEqual(len(results["results"]), 0)
        self.assertEqual(len(results["errors"]), 0)

    @pytest.mark.asyncio
    async def test_concurrency_control(self):
        """Test that concurrency is properly controlled."""
        # Create an executor with max_concurrency=2
        executor = AsyncFuzzExecutor(max_concurrency=2)
        
        # Track execution order
        execution_order = []
        
        async def test_op(name, delay):
            execution_order.append(f"{name}_start")
            await asyncio.sleep(delay)
            execution_order.append(f"{name}_end")
            return name
        
        # Create 3 operations with different delays
        operations = [
            (test_op, ["op1", 0.2], {}),
            (test_op, ["op2", 0.1], {}),
            (test_op, ["op3", 0.15], {})
        ]
        
        # Execute batch
        await executor.execute_batch(operations)
        
        # Check that at most 2 operations started before any ended
        # Find index of first end event
        first_end_idx = next(
            i for i, event in enumerate(execution_order) 
            if event.endswith("_end")
        )
        starts_before_any_end = execution_order[:first_end_idx]
        self.assertLessEqual(len(starts_before_any_end), 2)

    @pytest.mark.asyncio
    async def test_shutdown_no_tasks(self):
        """Test shutdown with no running tasks."""
        await self.executor.shutdown()
        self.assertEqual(len(self.executor._running_tasks), 0)

    @pytest.mark.asyncio
    async def test_shutdown_with_tasks(self):
        """Test shutdown with running tasks."""
        # Create some tasks
        async def long_task():
            try:
                await asyncio.sleep(10)
                return "Done"
            except asyncio.CancelledError:
                return "Cancelled"
        
        task1 = asyncio.create_task(self.executor._execute_and_track(long_task, [], {}))
        task2 = asyncio.create_task(self.executor._execute_and_track(long_task, [], {}))
        
        self.executor._running_tasks.add(task1)
        self.executor._running_tasks.add(task2)
        
        # Shutdown with short timeout
        await self.executor.shutdown(timeout=0.1)
        
        # Tasks should be cancelled
        self.assertTrue(task1.cancelled() or task1.done())
        self.assertTrue(task2.cancelled() or task2.done())
        
        # Running tasks set should be empty or contain only completed tasks
        for task in self.executor._running_tasks:
            self.assertTrue(task.done())


if __name__ == "__main__":
    unittest.main()
