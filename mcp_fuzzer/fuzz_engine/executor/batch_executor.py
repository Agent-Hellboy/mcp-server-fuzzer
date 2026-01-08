#!/usr/bin/env python3
"""
Batch Executor

This module contains execution orchestration logic for batch fuzzing.
"""

import logging
from typing import Any

from ...types import FuzzDataResult
from .async_executor import AsyncFuzzExecutor
from ..mutators import BatchMutator
from ..fuzzerreporter import ResultBuilder


class BatchExecutor:
    """Orchestrates batch fuzzing execution."""

    def __init__(
        self,
        transport: Any | None = None,
        batch_mutator: BatchMutator | None = None,
        executor: AsyncFuzzExecutor | None = None,
        result_builder: ResultBuilder | None = None,
        max_concurrency: int = 5,
    ):
        """
        Initialize the batch executor.

        Args:
            transport: Optional transport for sending requests to server
            batch_mutator: Batch mutator for generating batch requests
            executor: Async executor for running operations
            result_builder: Result builder for creating standardized results
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self.batch_mutator = batch_mutator or BatchMutator()
        self.executor = executor or AsyncFuzzExecutor(max_concurrency=max_concurrency)
        self.result_builder = result_builder or ResultBuilder()
        self._logger = logging.getLogger(__name__)

    async def execute(
        self,
        protocol_types: list[str] | None = None,
        runs: int = 5,
        phase: str = "aggressive",
        generate_only: bool = False,
    ) -> list[FuzzDataResult]:
        """
        Execute batch fuzzing runs.

        Args:
            protocol_types: List of protocol types to include in batches
            runs: Number of batch fuzzing runs
            phase: Fuzzing phase (realistic or aggressive)
            generate_only: If True, only generate fuzzing data without sending requests

        Returns:
            List of fuzzing results
        """
        if runs <= 0:
            return []

        results = []
        for run_index in range(runs):
            try:
                # Generate a batch request using batch mutator
                batch_request = await self.batch_mutator.mutate(
                    protocol_types=protocol_types, phase=phase
                )

                if not batch_request:
                    continue

                # Send the batch if needed
                server_response, server_error = await self._send_batch_request(
                    batch_request, generate_only
                )

                # Create result
                result = self.result_builder.build_batch_result(
                    run_index=run_index,
                    batch_request=batch_request,
                    server_response=server_response,
                    server_error=server_error,
                )
                results.append(result)

                self._logger.debug(f"Fuzzed batch request run {run_index + 1}")

            except Exception as e:
                self._logger.error(
                    "Error fuzzing batch request run %s: %s",
                    run_index + 1,
                    e,
                )
                results.append(
                    self.result_builder.build_batch_result(
                        run_index=run_index,
                        batch_request=[],
                        server_error=str(e),
                    )
                )

        return results

    async def _send_batch_request(
        self,
        batch_request: list[dict[str, Any]],
        generate_only: bool,
    ) -> tuple[dict[str, Any] | list[dict[str, Any]] | None, str | None]:
        """
        Send batch request to server if appropriate.

        Args:
            batch_request: Batch request to send
            generate_only: If True, don't send the request

        Returns:
            Tuple of (server_response, server_error)
        """
        server_response = None
        server_error = None

        if self.transport and not generate_only:
            try:
                # Handle batch request
                batch_responses = await self.transport.send_batch_request(batch_request)
                # Collate responses by ID
                server_response = self.transport.collate_batch_responses(
                    batch_request, batch_responses
                )

                self._logger.debug("Server accepted batch request")
            except Exception as server_exception:
                server_error = str(server_exception)
                self._logger.debug(
                    "Server rejected batch request: %s",
                    server_exception,
                )

        return server_response, server_error

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        await self.executor.shutdown()
