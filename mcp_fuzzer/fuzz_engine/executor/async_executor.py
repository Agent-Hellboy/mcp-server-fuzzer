#!/usr/bin/env python3
"""
Async Fuzz Executor

This module provides async execution capabilities for fuzzing operations,
including wrapping Hypothesis strategies to prevent deadlocks in asyncio.
"""

import asyncio
import functools
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from hypothesis import strategies as st


class AsyncFuzzExecutor:
    """Executes fuzzing operations asynchronously with controlled concurrency."""

    def __init__(self, max_concurrency: int = 5):
        """
        Initialize the executor.

        Args:
            max_concurrency: Maximum number of concurrent operations
        """
        self.max_concurrency = max_concurrency
        self._semaphore = None  # Will be created lazily when needed
        self._thread_pool = ThreadPoolExecutor(max_workers=max_concurrency)
        self._logger = logging.getLogger(__name__)

    def _get_semaphore(self):
        """Get or create the semaphore lazily."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        return self._semaphore

    @staticmethod
    def _func_name(func: Callable) -> str:
        return getattr(func, "__name__", "unknown")

    async def execute_batch(
        self, operations: list[tuple[Callable, list[Any], dict[str, Any]]]
    ) -> dict[str, list[Any]]:
        """
        Execute a batch of operations with controlled concurrency.

        Args:
            operations: List of (function, args, kwargs) tuples

        Returns:
            Dictionary with 'results' and 'errors' lists
        """
        results = []
        errors = []

        # Create tasks for all operations
        tasks = [
            asyncio.create_task(
                self._execute_single(func, args, kwargs),
                name=f"fuzz_operation_{i}_{self._func_name(func)}",
            )
            for i, (func, args, kwargs) in enumerate(operations)
        ]

        # Wait for all tasks to complete
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in completed:
            if isinstance(result, BaseException):
                # Preserve cancellation semantics
                if isinstance(result, asyncio.CancelledError):
                    raise result
                errors.append(result)
            else:
                results.append(result)

        return {"results": results, "errors": errors}

    async def _execute_single(
        self, func: Callable, args: list[Any], kwargs: dict[str, Any]
    ) -> Any:
        """
        Execute a single operation with semaphore-controlled concurrency.

        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            Result of the function execution
        """
        async with self._get_semaphore():
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                # Run synchronous functions in thread pool (support kwargs)
                loop = asyncio.get_running_loop()
                bound = functools.partial(func, *args, **kwargs)
                return await loop.run_in_executor(self._thread_pool, bound)
            except Exception as e:
                self._logger.warning(f"Error executing {self._func_name(func)}: {e}")
                raise

    async def run_hypothesis_strategy(self, strategy: st.SearchStrategy) -> Any:
        """
        Run a Hypothesis strategy in a thread pool to prevent asyncio deadlocks.

        Args:
            strategy: Hypothesis strategy to execute

        Returns:
            Generated value from the strategy
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._thread_pool, strategy.example)

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        self._thread_pool.shutdown(wait=True)
