#!/usr/bin/env python3
"""
Async executor for fuzzing operations.
"""

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple


class AsyncFuzzExecutor:
    """
    Executor for async fuzzing operations.

    This class handles the execution of fuzzing operations against MCP servers,
    providing concurrency control, error handling, and result aggregation.
    """

    def __init__(
        self,
        max_concurrency: int = 5,
        timeout: float = 30.0,
        retry_count: int = 1,
        retry_delay: float = 1.0,
    ):
        """
        Initialize the async executor.

        Args:
            max_concurrency: Maximum number of concurrent operations
            timeout: Default timeout for operations in seconds
            retry_count: Number of retries for failed operations
            retry_delay: Delay between retries in seconds
        """
        self._logger = logging.getLogger(__name__)
        self._max_concurrency = max_concurrency
        self._timeout = timeout
        self._retry_count = retry_count
        self._retry_delay = retry_delay
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._running_tasks: Set[asyncio.Task] = set()

    def _op_name(self, op: Callable[..., Awaitable[Any]]) -> str:
        """Get the name of an operation safely."""
        return getattr(op, "__name__", op.__class__.__name__)

    async def execute(
        self,
        operation: Callable[..., Awaitable[Any]],
        *args,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> Any:
        """
        Execute a single operation with timeout and error handling.

        Args:
            operation: Async callable to execute
            *args: Positional arguments for the operation
            timeout: Optional timeout override
            **kwargs: Keyword arguments for the operation

        Returns:
            Result of the operation

        Raises:
            asyncio.TimeoutError: If operation times out
            Exception: Any exception from the operation
        """
        timeout_value = timeout or self._timeout

        try:
            async with self._semaphore:
                return await asyncio.wait_for(
                    operation(*args, **kwargs),
                    timeout=timeout_value,
                )
        except asyncio.TimeoutError:
            self._logger.warning(
                "Operation timed out after %.2fs: %s",
                timeout_value,
                self._op_name(operation),
            )
            raise
        except asyncio.CancelledError:
            # Preserve cancellation
            raise
        except Exception as e:
            self._logger.debug(
                "Operation failed: %s - %s",
                self._op_name(operation),
                str(e),
                exc_info=True,
            )
            raise

    async def execute_with_retry(
        self,
        operation: Callable[..., Awaitable[Any]],
        *args,
        retry_count: Optional[int] = None,
        retry_delay: Optional[float] = None,
        **kwargs,
    ) -> Any:
        """
        Execute an operation with retries on failure.

        Args:
            operation: Async callable to execute
            *args: Positional arguments for the operation
            retry_count: Optional retry count override
            retry_delay: Optional retry delay override
            **kwargs: Keyword arguments for the operation

        Returns:
            Result of the operation

        Raises:
            Exception: If all retries fail
        """
        retries = retry_count if retry_count is not None else self._retry_count
        delay = retry_delay if retry_delay is not None else self._retry_delay

        last_error = None
        for attempt in range(retries + 1):
            try:
                return await self.execute(operation, *args, **kwargs)
            except asyncio.CancelledError:
                # Do not retry cancellations
                raise
            except Exception as e:
                last_error = e
                if attempt < retries:
                    self._logger.debug(
                        "Retry %d/%d for %s after error: %s",
                        attempt + 1,
                        retries,
                        self._op_name(operation),
                        str(e),
                    )
                    # Exponential backoff
                    await asyncio.sleep(delay * (2**attempt))
                else:
                    self._logger.debug(
                        "All retries failed for %s: %s",
                        self._op_name(operation),
                        str(e),
                    )

        assert last_error is not None
        raise last_error

    async def execute_batch(
        self,
        operations: List[Tuple[Callable[..., Awaitable[Any]], List, Dict]],
        collect_results: bool = True,
        collect_errors: bool = True,
    ) -> Dict[str, List]:
        """
        Execute a batch of operations concurrently with bounded concurrency.

        Args:
            operations: List of (operation, args, kwargs) tuples
            collect_results: Whether to collect successful results
            collect_errors: Whether to collect errors

        Returns:
            Dictionary with 'results' and 'errors' lists
        """

        async def _bounded_execute_and_track(op, args, kwargs):
            # Acquire semaphore before execution and release after
            async with self._semaphore:
                return await self._execute_and_track(op, args, kwargs)

        # Create bounded tasks that respect the semaphore limit
        tasks = []
        for op, args, kwargs in operations:
            task = asyncio.create_task(_bounded_execute_and_track(op, args, kwargs))
            self._running_tasks.add(task)
            task.add_done_callback(self._running_tasks.discard)
            tasks.append(task)

        results = []
        errors = []

        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                if collect_results:
                    results.append(result)
            except Exception as e:
                if collect_errors:
                    errors.append(e)

        return {
            "results": results,
            "errors": errors,
        }

    async def _execute_and_track(
        self,
        operation: Callable[..., Awaitable[Any]],
        args: List,
        kwargs: Dict,
    ) -> Any:
        """
        Execute an operation and track it.

        Args:
            operation: Async callable to execute
            args: Positional arguments for the operation
            kwargs: Keyword arguments for the operation

        Returns:
            Result of the operation
        """
        return await self.execute(operation, *args, **kwargs)

    async def shutdown(self, timeout: float = 5.0) -> None:
        """
        Shutdown the executor, waiting for running tasks to complete.

        Args:
            timeout: Maximum time to wait for tasks to complete
        """
        if not self._running_tasks:
            return

        self._logger.debug(
            "Shutting down executor with %d tasks",
            len(self._running_tasks),
        )

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._running_tasks, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            self._logger.warning(
                "Shutdown timed out with %d tasks still running",
                len(self._running_tasks),
            )
