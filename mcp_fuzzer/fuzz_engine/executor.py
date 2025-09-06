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
from typing import Any, Callable, Dict, List, Tuple

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
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._thread_pool = ThreadPoolExecutor(max_workers=max_concurrency)
        self._logger = logging.getLogger(__name__)

    async def execute_batch(
        self, operations: List[Tuple[Callable, List[Any], Dict[str, Any]]]
    ) -> Dict[str, List[Any]]:
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
        tasks = []
        for func, args, kwargs in operations:
            task = asyncio.create_task(self._execute_single(func, args, kwargs))
            tasks.append(task)

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
        self, func: Callable, args: List[Any], kwargs: Dict[str, Any]
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
        async with self._semaphore:
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    # Run synchronous functions in thread pool (support kwargs)
                    loop = asyncio.get_running_loop()
                    bound = functools.partial(func, *args, **kwargs)
                    return await loop.run_in_executor(self._thread_pool, bound)
            except Exception as e:
                self._logger.warning(f"Error executing {func.__name__}: {e}")
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
