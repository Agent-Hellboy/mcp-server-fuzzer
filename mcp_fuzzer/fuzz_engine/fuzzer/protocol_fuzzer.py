#!/usr/bin/env python3
"""
Protocol Fuzzer

This module contains the orchestration logic for fuzzing MCP protocol types.
"""

import asyncio
import inspect
import logging
from typing import Any, Dict, List, ClassVar, Tuple

from ..executor import AsyncFuzzExecutor
from ..strategy import ProtocolStrategies


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
        "CreateMessageRequest",
        "ListPromptsRequest",
        "GetPromptRequest",
        "ListRootsRequest",
        "SubscribeRequest",
        "UnsubscribeRequest",
        "CompleteRequest",
    )

    def __init__(self, transport=None, max_concurrency: int = 5):
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
        self, protocol_type: str, runs: int = 10, phase: str = "aggressive"
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a specific protocol type with specified phase and analyze responses.
        
        Args:
            protocol_type: Protocol type to fuzz
            runs: Number of fuzzing runs
            phase: Fuzzing phase (realistic or aggressive)
            
        Returns:
            List of fuzzing results
        """
        if runs <= 0:
            return []

        # Get the fuzzer method for this protocol type
        fuzzer_method = self.strategies.get_protocol_fuzzer_method(protocol_type)

        if not fuzzer_method:
            self._logger.error(f"Unknown protocol type: {protocol_type}")
            return []

        # Create operations for batch execution
        operations = []
        for i in range(runs):
            operations.append((
                self._fuzz_protocol_type_single_run,
                [protocol_type, fuzzer_method, i, phase],
                {}
            ))
        
        # Execute all operations in parallel with controlled concurrency
        batch_results = await self.executor.execute_batch(operations)
        
        # Process results
        results = []
        for result in batch_results["results"]:
            if result is not None:
                results.append(result)
        
        # Process errors
        for error in batch_results["errors"]:
            self._logger.error(f"Error fuzzing {protocol_type}: {error}")
            results.append({
                "protocol_type": protocol_type,
                "success": False,
                "exception": str(error),
            })
        
        return results

    async def _fuzz_protocol_type_single_run(
        self,
        protocol_type: str,
        fuzzer_method: Any,
        run_index: int,
        phase: str,
    ) -> Dict[str, Any]:
        """
        Execute a single fuzzing run for a protocol type.
        
        Args:
            protocol_type: Protocol type to fuzz
            fuzzer_method: Strategy method to generate fuzz data
            run_index: Run index (0-based)
            phase: Fuzzing phase
            
        Returns:
            Fuzzing result
        """
        try:
            # Generate fuzz data using the strategy with phase
            kwargs = (
                {"phase": phase}
                if "phase" in inspect.signature(fuzzer_method).parameters
                else {}
            )
            maybe_coro = fuzzer_method(**kwargs)
            if inspect.isawaitable(maybe_coro):
                fuzz_data = await maybe_coro
            else:
                fuzz_data = maybe_coro

            # Send the request to the server if transport is available
            server_response = None
            server_error = None

            if self.transport:
                try:
                    # Send envelope exactly as generated
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

            # Create the result entry
            result = {
                "protocol_type": protocol_type,
                "run": run_index + 1,
                "fuzz_data": fuzz_data,
                "success": True,
                "server_response": server_response,
                "server_error": server_error,
                "server_handled_malicious_input": server_error is not None,  # Good
            }

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

    async def fuzz_protocol_type_both_phases(
        self, protocol_type: str, runs_per_phase: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
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
    ) -> Dict[str, List[Dict[str, Any]]]:
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
        
        # Wait for all tasks to complete
        for protocol_type, task in tasks:
            try:
                results = await task
                all_results[protocol_type] = results
            except Exception as e:
                self._logger.error(f"Failed to fuzz {protocol_type}: {e}")
                all_results[protocol_type] = []

        return all_results
    
    async def _fuzz_single_protocol_type(
        self,
        protocol_type: str,
        runs: int,
        phase: str,
    ) -> List[Dict[str, Any]]:
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
            [
                r
                for r in results
                if r.get("server_handled_malicious_input", False)
            ]
        )
        total = len(results)
        
        self._logger.info(
            f"Completed {protocol_type}: {successful}/{total} successful, "
            f"{server_rejections} server rejections"
        )
        
        return results
    
    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        await self.executor.shutdown()