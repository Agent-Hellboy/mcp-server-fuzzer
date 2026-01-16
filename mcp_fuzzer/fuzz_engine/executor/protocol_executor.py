#!/usr/bin/env python3
"""
Protocol Executor

This module contains execution orchestration logic for protocol fuzzing.
"""

import asyncio
import logging
from typing import Any, ClassVar

from ...types import FuzzDataResult
from .async_executor import AsyncFuzzExecutor
from .invariants import (
    verify_response_invariants,
    InvariantViolation,
    verify_batch_responses,
)
from ..mutators import ProtocolMutator, BatchMutator
from ..fuzzerreporter import ResultBuilder, ResultCollector
from ... import spec_guard


class ProtocolExecutor:
    """Orchestrates protocol fuzzing execution."""

    # Protocol types supported for fuzzing
    PROTOCOL_TYPES: ClassVar[tuple[str, ...]] = (
        "InitializeRequest",
        "ProgressNotification",
        "CancelNotification",
        "ListResourcesRequest",
        "ReadResourceRequest",
        "SetLevelRequest",
        "GenericJSONRPCRequest",
        "CallToolResult",
        "SamplingMessage",
        "CreateMessageRequest",
        "ListPromptsRequest",
        "GetPromptRequest",
        "ListRootsRequest",
        "SubscribeRequest",
        "UnsubscribeRequest",
        "CompleteRequest",
        "ListResourceTemplatesRequest",
        "ElicitRequest",
        "PingRequest",
        # Result schemas
        "InitializeResult",
        "ListResourcesResult",
        "ListResourceTemplatesResult",
        "ReadResourceResult",
        "ListPromptsResult",
        "GetPromptResult",
        "ListToolsResult",
        "CompleteResult",
        "CreateMessageResult",
        "ListRootsResult",
        "PingResult",
        "ElicitResult",
        # Notification schemas
        "LoggingMessageNotification",
        "ResourceListChangedNotification",
        "ResourceUpdatedNotification",
        "PromptListChangedNotification",
        "ToolListChangedNotification",
        "RootsListChangedNotification",
        # Content block schemas
        "TextContent",
        "ImageContent",
        "AudioContent",
        # Resource schemas
        "Resource",
        "ResourceTemplate",
        "TextResourceContents",
        "BlobResourceContents",
        # Tool schemas
        "Tool",
    )
    # Seconds to wait for invariant validation of batch responses
    BATCH_VALIDATION_TIMEOUT: ClassVar[float] = 5.0

    def __init__(
        self,
        transport: Any | None = None,
        mutator: ProtocolMutator | None = None,
        batch_mutator: BatchMutator | None = None,
        executor: AsyncFuzzExecutor | None = None,
        result_builder: ResultBuilder | None = None,
        result_collector: ResultCollector | None = None,
        max_concurrency: int = 5,
    ):
        """
        Initialize the protocol executor.

        Args:
            transport: Optional transport for sending requests to server
            mutator: Protocol mutator for generating fuzzed messages
            batch_mutator: Batch mutator for generating batch requests
            executor: Async executor for running operations
            result_builder: Result builder for creating standardized results
            result_collector: Result collector for aggregating results
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self.mutator = mutator or ProtocolMutator()
        self.batch_mutator = batch_mutator or BatchMutator()
        self.executor = executor or AsyncFuzzExecutor(max_concurrency=max_concurrency)
        self.result_builder = result_builder or ResultBuilder()
        self.collector = result_collector or ResultCollector()
        self._logger = logging.getLogger(__name__)
        # Bound concurrent protocol-type tasks
        self._type_semaphore = None  # Will be created lazily when needed

    def _get_type_semaphore(self):
        """Get or create the type semaphore lazily."""
        if self._type_semaphore is None:
            self._type_semaphore = asyncio.Semaphore(self.executor.max_concurrency)
        return self._type_semaphore

    async def execute(
        self,
        protocol_type: str,
        runs: int = 10,
        phase: str = "aggressive",
        generate_only: bool = False,
    ) -> list[FuzzDataResult]:
        """
        Execute fuzzing runs for a protocol type.

        Args:
            protocol_type: Protocol type to fuzz
            runs: Number of fuzzing runs
            phase: Fuzzing phase (realistic or aggressive)
            generate_only: If True, only generate fuzzing data without sending requests

        Returns:
            List of fuzzing results
        """
        if runs <= 0:
            return []

        # Get the fuzzer method for this protocol type
        fuzzer_method = self.mutator.get_fuzzer_method(protocol_type, phase)
        if not fuzzer_method:
            return []

        # Prepare fuzzing operations
        operations = []
        for i in range(runs):
            operations.append(
                (
                    self._execute_single_run,
                    [protocol_type, i, phase, generate_only],
                    {},
                )
            )

        # Execute operations and process results
        return await self._execute_and_process_operations(operations, protocol_type)

    async def _execute_and_process_operations(
        self,
        operations: list[tuple[Any, list[Any], dict[str, Any]]],
        protocol_type: str,
    ) -> list[FuzzDataResult]:
        """
        Execute operations and process results.

        Args:
            operations: List of operations to execute
            protocol_type: Protocol type being fuzzed

        Returns:
            List of fuzzing results
        """
        # Execute all operations in parallel with controlled concurrency
        batch_results = await self.executor.execute_batch(operations)

        # Process results
        results = [
            result for result in batch_results["results"] if result is not None
        ]

        # Process errors
        for error in batch_results["errors"]:
            if isinstance(error, asyncio.CancelledError):
                raise error
            self._logger.error("Error fuzzing %s: %s", protocol_type, error)
            results.append(
                {
                    "protocol_type": protocol_type,
                    # Use -1 to indicate a batch-level error without a run index.
                    "run": -1,
                    "fuzz_data": {},
                    "success": False,
                    "exception": str(error),
                }
            )

        return results

    async def _execute_single_run(
        self,
        protocol_type: str,
        run_index: int,
        phase: str,
        generate_only: bool = False,
    ) -> FuzzDataResult:
        """
        Execute a single fuzzing run for a protocol type.

        Args:
            protocol_type: Protocol type to fuzz
            run_index: Run index (0-based)
            phase: Fuzzing phase
            generate_only: If True, only generate fuzzing data without sending requests

        Returns:
            Fuzzing result
        """
        try:
            # Generate fuzz data using mutator
            fuzz_data = await self.mutator.mutate(protocol_type, phase)

            # Send request if needed
            server_response, server_error = await self._send_fuzzed_request(
                protocol_type, fuzz_data, generate_only
            )

            # Verify invariants if we have a server response
            invariant_violations = []
            if server_response is not None and not generate_only:
                try:
                    # Batch: either a raw list of responses or a collated mapping
                    # {id: response}
                    if isinstance(server_response, list) or (
                        isinstance(server_response, dict)
                        and "jsonrpc" not in server_response
                    ):
                        try:
                            # Handle batch responses with timeout to prevent hanging
                            batch = await asyncio.wait_for(
                                verify_batch_responses(server_response),
                                timeout=self.BATCH_VALIDATION_TIMEOUT,
                            )
                            viols = [str(v) for k, v in batch.items() if v is not True]
                            invariant_violations.extend(viols)
                        except asyncio.TimeoutError:
                            invariant_violations.append("Batch validation timed out")
                            self._logger.warning(
                                "Batch validation timeout in %s run %s",
                                protocol_type,
                                run_index + 1,
                            )
                    else:
                        verify_response_invariants(server_response)
                except InvariantViolation as e:
                    invariant_violations.append(str(e))
                    self._logger.warning(
                        "Invariant violation in %s run %s: %s",
                        protocol_type,
                        run_index + 1,
                        e,
                    )

            spec_checks: list[dict[str, Any]] = []
            spec_scope: str | None = None
            if isinstance(server_response, dict) and not generate_only:
                payload = server_response.get("result", server_response)
                method = (
                    fuzz_data.get("method") if isinstance(fuzz_data, dict) else None
                )
                spec_checks, spec_scope = spec_guard.get_spec_checks_for_method(
                    method, payload
                )

            # Create the result
            result = self.result_builder.build_protocol_result(
                protocol_type=protocol_type,
                run_index=run_index,
                fuzz_data=fuzz_data,
                server_response=server_response,
                server_error=server_error,
                invariant_violations=invariant_violations,
                spec_checks=spec_checks,
                spec_scope=spec_scope,
            )

            self._logger.debug(f"Fuzzed {protocol_type} run {run_index + 1}")
            return result

        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._logger.error(
                "Error fuzzing %s run %s: %s",
                protocol_type,
                run_index + 1,
                e,
            )
            return {
                "protocol_type": protocol_type,
                "run": run_index + 1,
                "fuzz_data": {},
                "success": False,
                "exception": str(e),
            }

    async def _send_fuzzed_request(
        self,
        protocol_type: str,
        fuzz_data: dict[str, Any] | list[dict[str, Any]],
        generate_only: bool,
    ) -> tuple[dict[str, Any] | list[dict[str, Any]] | None, str | None]:
        """
        Send fuzzed request to server if appropriate.

        Args:
            protocol_type: Protocol type being fuzzed
            fuzz_data: Fuzz data to send
            generate_only: If True, don't send the request

        Returns:
            Tuple of (server_response, server_error)
        """
        server_response = None
        server_error = None

        if self.transport and not generate_only:
            try:
                # Check if this is a batch request (list of requests)
                if isinstance(fuzz_data, list):
                    # Handle batch request
                    batch_responses = await self.transport.send_batch_request(fuzz_data)
                    # Collate responses by ID
                    server_response = self.transport.collate_batch_responses(
                        fuzz_data, batch_responses
                    )
                else:
                    # Send single envelope exactly as generated
                    server_response = await self.transport.send_raw(fuzz_data)

                self._logger.debug(
                    f"Server accepted fuzzed envelope for {protocol_type}"
                )
            except Exception as server_exception:
                server_error = str(server_exception)
                self._logger.debug(
                    "Server rejected fuzzed envelope: %s",
                    server_exception,
                )

        return server_response, server_error

    async def execute_both_phases(
        self, protocol_type: str, runs_per_phase: int = 5
    ) -> dict[str, list[FuzzDataResult]]:
        """
        Execute fuzzing in both realistic and aggressive phases.

        Args:
            protocol_type: Protocol type to fuzz
            runs_per_phase: Number of runs per phase

        Returns:
            Dictionary with results for each phase
        """
        results = {}

        self._logger.info(f"Running two-phase fuzzing for {protocol_type}")

        # Phase 1: Realistic fuzzing
        self._logger.info(f"Phase 1: Realistic fuzzing for {protocol_type}")
        results["realistic"] = await self.execute(
            protocol_type, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        self._logger.info(f"Phase 2: Aggressive fuzzing for {protocol_type}")
        results["aggressive"] = await self.execute(
            protocol_type, runs=runs_per_phase, phase="aggressive"
        )

        return results

    async def execute_all_types(
        self, runs_per_type: int = 5, phase: str = "aggressive"
    ) -> dict[str, list[FuzzDataResult]]:
        """
        Execute fuzzing for all known protocol types asynchronously.

        Args:
            runs_per_type: Number of runs per protocol type
            phase: Fuzzing phase

        Returns:
            Dictionary with results for each protocol type
        """
        if runs_per_type <= 0:
            return {}

        all_results = {}

        # Create tasks for each protocol type with bounded concurrency
        tasks = []
        sem = self._get_type_semaphore()

        async def _run(pt: str) -> list[dict[str, Any]]:
            async with sem:
                return await self._execute_single_type(pt, runs_per_type, phase)

        async def _run_with_type(
            pt: str,
        ) -> tuple[str, list[dict[str, Any]], Exception | None]:
            try:
                results = await asyncio.wait_for(_run(pt), timeout=30.0)
                return pt, results, None
            except Exception as exc:
                return pt, [], exc

        for protocol_type in self.PROTOCOL_TYPES:
            tasks.append(
                asyncio.create_task(
                    _run_with_type(protocol_type),
                    name=f"fuzz_protocol_{protocol_type}",
                )
            )

        # Process tasks as they complete for more responsive timeouts.
        for task in asyncio.as_completed(tasks):
            try:
                protocol_type, results, exc = await task
            except Exception as exc:
                self._logger.error("Failed to fuzz protocol types: %s", exc)
                continue

            if exc is None:
                all_results[protocol_type] = results
            elif isinstance(exc, asyncio.TimeoutError):
                self._logger.error("Timeout while fuzzing %s", protocol_type)
                all_results[protocol_type] = []
            else:
                self._logger.error("Failed to fuzz %s: %s", protocol_type, exc)
                all_results[protocol_type] = []

        return all_results

    async def _execute_single_type(
        self,
        protocol_type: str,
        runs: int,
        phase: str,
    ) -> list[FuzzDataResult]:
        """
        Execute fuzzing for a single protocol type and log statistics.

        Args:
            protocol_type: Protocol type to fuzz
            runs: Number of runs
            phase: Fuzzing phase

        Returns:
            List of fuzzing results
        """
        self._logger.info(f"Starting to fuzz protocol type: {protocol_type}")

        results = await self.execute(protocol_type, runs, phase)

        # Log summary
        successful = len([r for r in results if r.get("success", False)])
        server_rejections = len(
            [r for r in results if r.get("server_rejected_input", False)]
        )
        total = len(results)

        self._logger.info(
            "Completed %s: %d/%d successful, %d server rejections",
            protocol_type,
            successful,
            total,
            server_rejections,
        )

        return results

    async def execute_batch_requests(
        self,
        protocol_types: list[str] | None = None,
        runs: int = 5,
        phase: str = "aggressive",
        generate_only: bool = False,
    ) -> list[FuzzDataResult]:
        """
        Execute fuzzing using JSON-RPC batch requests with mixed protocol types.

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

                # Send the batch
                server_response, server_error = await self._send_fuzzed_request(
                    "BatchRequest", batch_request, generate_only
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

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        await self.executor.shutdown()
