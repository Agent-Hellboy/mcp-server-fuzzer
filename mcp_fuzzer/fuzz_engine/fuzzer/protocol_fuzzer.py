#!/usr/bin/env python3
"""
Protocol Fuzzer

This module contains the orchestration logic for fuzzing MCP protocol types.
"""

import asyncio
import inspect
import logging
from typing import Any, Dict, List, ClassVar, Optional, Tuple, Callable, Union

from ...types import FuzzDataResult

from ..executor import AsyncFuzzExecutor
from ..strategy import ProtocolStrategies
from ..invariants import (
    verify_response_invariants,
    InvariantViolation,
    verify_batch_responses,
)


class ProtocolFuzzer:
    """Orchestrates fuzzing of MCP protocol types."""

    # Protocol types supported for fuzzing
    PROTOCOL_TYPES: ClassVar[Tuple[str, ...]] = (
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

    def __init__(self, transport: Optional[Any] = None, max_concurrency: int = 5):
        """
        Initialize the protocol fuzzer.

        Args:
            transport: Optional transport for sending requests to server
            max_concurrency: Maximum number of concurrent fuzzing operations
        """
        self.strategies = ProtocolStrategies()
        self.request_id_counter = 0
        self.transport = transport
        self.executor = AsyncFuzzExecutor(max_concurrency=max_concurrency)
        self._logger = logging.getLogger(__name__)
        # Bound concurrent protocol-type tasks
        self._type_semaphore = asyncio.Semaphore(max_concurrency)

    def _get_request_id(self) -> int:
        """Generate a request ID for JSON-RPC requests."""
        self.request_id_counter += 1
        return self.request_id_counter

    async def fuzz_protocol_type(
        self,
        protocol_type: str,
        runs: int = 10,
        phase: str = "aggressive",
        generate_only: bool = False,
    ) -> List[FuzzDataResult]:
        """
        Fuzz a specific protocol type with specified phase and analyze responses.

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
        fuzzer_method = self._get_fuzzer_method(protocol_type, phase)
        if not fuzzer_method:
            return []

        # Prepare fuzzing operations
        operations = self._prepare_fuzzing_operations(
            protocol_type, fuzzer_method, runs, phase, generate_only
        )

        # Execute operations and process results
        return await self._execute_and_process_operations(operations, protocol_type)

    def _get_fuzzer_method(
        self, protocol_type: str, phase: str = "aggressive"
    ) -> Optional[Callable[..., Dict[str, Any]]]:
        """
        Get the appropriate fuzzer method for a protocol type and phase.

        Args:
            protocol_type: Protocol type to get fuzzer method for
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Fuzzer method or None if not found
        """
        fuzzer_method = self.strategies.get_protocol_fuzzer_method(protocol_type, phase)
        if not fuzzer_method:
            self._logger.error(
                f"Unknown protocol type: {protocol_type} for phase: {phase}"
            )
            return None
        return fuzzer_method

    def _prepare_fuzzing_operations(
        self,
        protocol_type: str,
        fuzzer_method: Callable[..., Dict[str, Any]],
        runs: int,
        phase: str,
        generate_only: bool,
    ) -> List[Tuple[Callable, List[Any], Dict[str, Any]]]:
        """
        Prepare operations for batch execution.

        Args:
            protocol_type: Protocol type to fuzz
            fuzzer_method: Strategy method to generate fuzz data
            runs: Number of runs
            phase: Fuzzing phase
            generate_only: If True, only generate fuzzing data

        Returns:
            List of operations for batch execution
        """
        operations = []
        for i in range(runs):
            operations.append(
                (
                    self._fuzz_protocol_type_single_run,
                    [protocol_type, fuzzer_method, i, phase, generate_only],
                    {},
                )
            )
        return operations

    async def _execute_and_process_operations(
        self,
        operations: List[Tuple[Callable, List[Any], Dict[str, Any]]],
        protocol_type: str,
    ) -> List[FuzzDataResult]:
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
        results = []
        for result in batch_results["results"]:
            if result is not None:
                results.append(result)

        # Process errors
        for error in batch_results["errors"]:
            if isinstance(error, asyncio.CancelledError):
                raise error
            self._logger.error("Error fuzzing %s: %s", protocol_type, error)
            results.append(
                {
                    "protocol_type": protocol_type,
                    "success": False,
                    "exception": str(error),
                }
            )

        return results

    async def _fuzz_protocol_type_single_run(
        self,
        protocol_type: str,
        fuzzer_method: Callable[..., Dict[str, Any]],
        run_index: int,
        phase: str,
        generate_only: bool = False,
    ) -> FuzzDataResult:
        """
        Execute a single fuzzing run for a protocol type.

        Args:
            protocol_type: Protocol type to fuzz
            fuzzer_method: Strategy method to generate fuzz data
            run_index: Run index (0-based)
            phase: Fuzzing phase
            generate_only: If True, only generate fuzzing data without sending requests

        Returns:
            Fuzzing result
        """
        try:
            # Generate fuzz data
            fuzz_data = await self._generate_fuzz_data(fuzzer_method, phase)

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

            # Create the result
            result = self._create_fuzz_result(
                protocol_type, run_index, fuzz_data, server_response, server_error
            )

            # Add invariant violations to the result
            if invariant_violations:
                result["invariant_violations"] = invariant_violations

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
                "fuzz_data": None,
                "success": False,
                "exception": str(e),
            }

    async def _generate_fuzz_data(
        self, fuzzer_method: Callable[..., Dict[str, Any]], phase: str
    ) -> Dict[str, Any]:
        """
        Generate fuzz data using the strategy method.

        Args:
            fuzzer_method: Strategy method to generate fuzz data
            phase: Fuzzing phase

        Returns:
            Generated fuzz data
        """
        # Check if method accepts phase parameter
        kwargs = (
            {"phase": phase}
            if "phase" in inspect.signature(fuzzer_method).parameters
            else {}
        )

        # Execute the fuzzer method
        maybe_coro = fuzzer_method(**kwargs)
        if inspect.isawaitable(maybe_coro):
            return await maybe_coro
        else:
            return maybe_coro

    async def _send_fuzzed_request(
        self,
        protocol_type: str,
        fuzz_data: Union[Dict[str, Any], List[Dict[str, Any]]],
        generate_only: bool,
    ) -> Tuple[
        Optional[Union[Dict[str, Any], List[Any], Dict[Any, Dict[str, Any]]]],
        Optional[str],
    ]:
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

    def _create_fuzz_result(
        self,
        protocol_type: str,
        run_index: int,
        fuzz_data: Dict[str, Any],
        server_response: Optional[
            Union[Dict[str, Any], List[Any], Dict[Any, Dict[str, Any]]]
        ],
        server_error: Optional[str],
    ) -> FuzzDataResult:
        """
        Create a standardized result dictionary for a fuzzing run.

        Args:
            protocol_type: Protocol type being fuzzed
            run_index: Run index (0-based)
            fuzz_data: Generated fuzz data
            server_response: Response from server, if any
            server_error: Error from server, if any

        Returns:
            Result dictionary
        """
        return {
            "protocol_type": protocol_type,
            "run": run_index + 1,
            "fuzz_data": fuzz_data,
            "success": server_error is None,
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "invariant_violations": [],  # Will be populated if violations occur
        }

    async def fuzz_protocol_type_both_phases(
        self, protocol_type: str, runs_per_phase: int = 5
    ) -> Dict[str, List[FuzzDataResult]]:
        """
        Fuzz a protocol type in both realistic and aggressive phases.

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
        results["realistic"] = await self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        self._logger.info(f"Phase 2: Aggressive fuzzing for {protocol_type}")
        results["aggressive"] = await self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="aggressive"
        )

        return results

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5, phase: str = "aggressive"
    ) -> Dict[str, List[FuzzDataResult]]:
        """
        Fuzz all known protocol types asynchronously.

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
        sem = self._type_semaphore

        async def _run(pt: str) -> List[Dict[str, Any]]:
            async with sem:
                return await self._fuzz_single_protocol_type(pt, runs_per_type, phase)

        for protocol_type in self.PROTOCOL_TYPES:
            task = asyncio.create_task(_run(protocol_type))
            tasks.append((protocol_type, task))

        # Wait for all tasks to complete with timeout
        for protocol_type, task in tasks:
            try:
                # Add a timeout to prevent hanging indefinitely
                results = await asyncio.wait_for(task, timeout=30.0)
                all_results[protocol_type] = results
            except asyncio.TimeoutError:
                self._logger.error(f"Timeout while fuzzing {protocol_type}")
                all_results[protocol_type] = []
                # Cancel the task to avoid orphaned tasks
                task.cancel()
            except Exception as e:
                self._logger.error(f"Failed to fuzz {protocol_type}: {e}")
                all_results[protocol_type] = []

        return all_results

    async def _fuzz_single_protocol_type(
        self,
        protocol_type: str,
        runs: int,
        phase: str,
    ) -> List[FuzzDataResult]:
        """
        Fuzz a single protocol type and log statistics.

        Args:
            protocol_type: Protocol type to fuzz
            runs: Number of runs
            phase: Fuzzing phase

        Returns:
            List of fuzzing results
        """
        self._logger.info(f"Starting to fuzz protocol type: {protocol_type}")

        results = await self.fuzz_protocol_type(protocol_type, runs, phase)

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

    async def fuzz_batch_requests(
        self,
        protocol_types: List[str] = None,
        runs: int = 5,
        phase: str = "aggressive",
        generate_only: bool = False,
    ) -> List[FuzzDataResult]:
        """
        Fuzz using JSON-RPC batch requests with mixed protocol types.

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
                # Generate a batch request
                batch_request = self.strategies.generate_batch_request(
                    protocol_types=protocol_types, phase=phase
                )

                if not batch_request:
                    continue

                # Send the batch
                server_response, server_error = await self._send_fuzzed_request(
                    "BatchRequest", batch_request, generate_only
                )

                # Create result
                result = self._create_batch_fuzz_result(
                    run_index, batch_request, server_response, server_error
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
                    {
                        "protocol_type": "BatchRequest",
                        "run": run_index + 1,
                        "fuzz_data": None,
                        "success": False,
                        "exception": str(e),
                    }
                )

        return results

    def _create_batch_fuzz_result(
        self,
        run_index: int,
        batch_request: List[Dict[str, Any]],
        server_response: Optional[
            Union[Dict[str, Any], List[Any], Dict[Any, Dict[str, Any]]]
        ],
        server_error: Optional[str],
    ) -> FuzzDataResult:
        """
        Create a standardized result dictionary for a batch fuzzing run.

        Args:
            run_index: Run index (0-based)
            batch_request: Generated batch request
            server_response: Response from server, if any
            server_error: Error from server, if any

        Returns:
            Result dictionary
        """
        return {
            "protocol_type": "BatchRequest",
            "run": run_index + 1,
            "fuzz_data": batch_request,
            "success": server_error is None,
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "batch_size": len(batch_request),
            "invariant_violations": [],  # Will be populated if violations occur
        }

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        await self.executor.shutdown()
