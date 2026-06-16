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
from types import TracebackType
from typing import Any, Callable


class AsyncFuzzExecutor:
    """Executes fuzzing operations asynchronously with controlled concurrency."""

    def __init__(self, max_concurrency: int = 5):
        """
        Initialize the executor.

        Args:
            max_concurrency: Maximum number of concurrent operations
        """
        self.max_concurrency = max(1, max_concurrency)
        self._semaphore: asyncio.Semaphore | None = None
        self._semaphore_loop: asyncio.AbstractEventLoop | None = None
        self._thread_pool: ThreadPoolExecutor | None = None
        self._shutdown = False
        self._logger = logging.getLogger(__name__)
        self._ensure_thread_pool()

    def _ensure_thread_pool(self) -> None:
        if self._thread_pool is None:
            self._thread_pool = ThreadPoolExecutor(max_workers=self.max_concurrency)

    def _get_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
            self._semaphore_loop = loop
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
        if self._shutdown:
            raise RuntimeError("AsyncFuzzExecutor has been shut down")

        results = []
        errors = []

        tasks = [
            asyncio.create_task(
                self._execute_single(func, args, kwargs),
                name=f"fuzz_operation_{i}_{self._func_name(func)}",
            )
            for i, (func, args, kwargs) in enumerate(operations)
        ]

        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for result in completed:
            if isinstance(result, BaseException):
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
        if self._shutdown:
            raise RuntimeError("AsyncFuzzExecutor has been shut down")

        async with self._get_semaphore():
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                loop = asyncio.get_running_loop()
                bound = functools.partial(func, *args, **kwargs)
                self._ensure_thread_pool()
                return await loop.run_in_executor(self._thread_pool, bound)
            except Exception as e:
                self._logger.warning(
                    "Error executing %s: %s", self._func_name(func), e
                )
                raise

    async def run_hypothesis_strategy(self, strategy) -> Any:
        """
        Run a Hypothesis strategy in a thread pool to prevent asyncio deadlocks.

        Args:
            strategy: Hypothesis strategy to execute

        Returns:
            Generated value from the strategy
        """
        if self._shutdown:
            raise RuntimeError("AsyncFuzzExecutor has been shut down")
        loop = asyncio.get_running_loop()
        self._ensure_thread_pool()
        return await loop.run_in_executor(self._thread_pool, strategy.example)

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        if self._shutdown:
            return
        self._shutdown = True
        if self._thread_pool is not None:
            self._thread_pool.shutdown(wait=True)
            self._thread_pool = None
        self._semaphore = None
        self._semaphore_loop = None

    async def __aenter__(self) -> "AsyncFuzzExecutor":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.shutdown()
