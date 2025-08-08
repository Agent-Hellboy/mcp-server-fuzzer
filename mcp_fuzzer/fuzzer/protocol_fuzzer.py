#!/usr/bin/env python3
"""
Protocol Fuzzer

This module contains the orchestration logic for fuzzing MCP protocol types.
"""

import json
import logging
import traceback
from typing import Any, Dict, List

from ..strategy import ProtocolStrategies


class ProtocolFuzzer:
    """Orchestrates fuzzing of MCP protocol types."""

    def __init__(self, transport=None):
        self.strategies = ProtocolStrategies()
        self.request_id_counter = 0
        self.transport = transport

    def _get_request_id(self) -> int:
        """Generate a request ID for JSON-RPC requests."""
        self.request_id_counter += 1
        return self.request_id_counter

    async def fuzz_protocol_type(
        self, protocol_type: str, runs: int = 10, phase: str = "aggressive"
    ) -> List[Dict[str, Any]]:
        """Fuzz a specific protocol type with specified phase."""
        results = []

        # Get the fuzzer method for this protocol type
        fuzzer_method = self.strategies.get_protocol_fuzzer_method(protocol_type)

        if not fuzzer_method:
            logging.error(f"Unknown protocol type: {protocol_type}")
            return []

        for i in range(runs):
            fuzz_data = None
            try:
                # Generate fuzz data using the strategy with phase
                if (
                    hasattr(fuzzer_method, "__code__")
                    and "phase" in fuzzer_method.__code__.co_varnames
                ):
                    fuzz_data = fuzzer_method(phase=phase)
                else:
                    fuzz_data = fuzzer_method()

                preview = json.dumps(fuzz_data, indent=2)[:200]
                logging.info(
                    "Fuzzing %s (%s phase, run %d/%d) with data: %s...",
                    protocol_type,
                    phase,
                    i + 1,
                    runs,
                    preview,
                )

                # Actually send the request to the server if transport is available
                server_response = None
                server_error = None
                if self.transport:
                    try:
                        server_response = await self._send_fuzz_request(fuzz_data)
                    except Exception as server_exception:
                        server_error = str(server_exception)
                        logging.debug(
                            f"Server rejected fuzz data (expected): {server_exception}"
                        )

                # Record the result
                result = {
                    "protocol_type": protocol_type,
                    "run": i + 1,
                    "fuzz_data": fuzz_data,
                    "success": True,  # Success means we sent the fuzz data
                    "server_response": server_response,
                    "server_error": server_error,
                    "server_handled_malicious_input": server_error is not None,  # Good
                }

                results.append(result)

            except Exception as e:
                logging.warning(f"Exception during fuzzing {protocol_type}: {e}")
                results.append(
                    {
                        "protocol_type": protocol_type,
                        "run": i + 1,
                        "fuzz_data": fuzz_data,
                        "exception": str(e),
                        "success": False,
                    }
                )

        return results

    async def _send_fuzz_request(self, fuzz_data: Dict[str, Any]) -> Any:
        """Send a fuzz request to the server and return the response."""
        if not self.transport:
            return None

        # Extract method and params from fuzz data
        method = fuzz_data.get("method", "unknown")
        params = fuzz_data.get("params", {})

        # For notifications, we don't expect a response
        if method.startswith("notifications/"):
            # Send notification and return a dummy response
            await self.transport.send_request(method, params)
            return {"status": "notification_sent"}
        else:
            # Send regular request and wait for response
            return await self.transport.send_request(method, params)

    async def fuzz_protocol_type_both_phases(
        self, protocol_type: str, runs_per_phase: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz a protocol type in both realistic and aggressive phases."""
        results = {}

        logging.info(f"Running two-phase fuzzing for {protocol_type}")

        # Phase 1: Realistic fuzzing
        logging.info(f"Phase 1: Realistic fuzzing for {protocol_type}")
        results["realistic"] = await self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        logging.info(f"Phase 2: Aggressive fuzzing for {protocol_type}")
        results["aggressive"] = await self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="aggressive"
        )

        return results

    def fuzz_protocol_type_sync(
        self, protocol_type: str, runs: int = 10, phase: str = "aggressive"
    ) -> List[Dict[str, Any]]:
        """Sync version of fuzz_protocol_type for tests and non-async usage."""
        results = []

        # Get the fuzzer method for this protocol type
        fuzzer_method = self.strategies.get_protocol_fuzzer_method(protocol_type)

        if not fuzzer_method:
            logging.error(f"Unknown protocol type: {protocol_type}")
            return []

        for i in range(runs):
            try:
                # Generate fuzz data using the strategy with phase
                if (
                    hasattr(fuzzer_method, "__code__")
                    and "phase" in fuzzer_method.__code__.co_varnames
                ):
                    fuzz_data = fuzzer_method(phase=phase)
                else:
                    fuzz_data = fuzzer_method()

                # For sync version, we don't actually send to transport
                # This is mainly for generating test data
                result = {
                    "protocol_type": protocol_type,
                    "run": i + 1,
                    "fuzz_data": fuzz_data,
                    "success": True,
                    "server_response": None,
                    "server_error": None,
                    "server_handled_malicious_input": False,
                }

                results.append(result)

                logging.debug(f"Generated fuzz data for {protocol_type} run {i + 1}")

            except Exception as e:
                logging.error(f"Error fuzzing {protocol_type} run {i + 1}: {e}")
                results.append(
                    {
                        "protocol_type": protocol_type,
                        "run": i + 1,
                        "fuzz_data": None,
                        "success": False,
                        "exception": str(e),
                        "traceback": traceback.format_exc(),
                    }
                )

        return results

    def fuzz_all_protocol_types_sync(
        self, runs_per_type: int = 5, phase: str = "aggressive"
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Sync version of fuzz_all_protocol_types for tests and non-async usage."""
        protocol_types = [
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
        ]

        all_results = {}

        for protocol_type in protocol_types:
            logging.info(f"Starting to fuzz protocol type: {protocol_type}")

            try:
                results = self.fuzz_protocol_type_sync(
                    protocol_type, runs_per_type, phase
                )
                all_results[protocol_type] = results

                # Calculate statistics
                successful = len([r for r in results if r.get("success", False)])
                exceptions = len([r for r in results if not r.get("success", False)])

                logging.info(
                    "Completed fuzzing %s: %d successful, %d exceptions out of %d runs",
                    protocol_type,
                    successful,
                    exceptions,
                    runs_per_type,
                )

            except Exception as e:
                logging.error(f"Failed to fuzz protocol type {protocol_type}: {e}")
                all_results[protocol_type] = [{"error": str(e)}]

        return all_results

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5, phase: str = "aggressive"
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz all protocol types."""
        protocol_types = [
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
        ]

        all_results = {}

        for protocol_type in protocol_types:
            logging.info(f"Starting to fuzz protocol type: {protocol_type}")

            try:
                results = await self.fuzz_protocol_type(
                    protocol_type, runs_per_type, phase
                )
                all_results[protocol_type] = results

                # Calculate statistics
                successful = len([r for r in results if r.get("success", False)])
                exceptions = len([r for r in results if not r.get("success", False)])
                server_rejections = len(
                    [
                        r
                        for r in results
                        if r.get("server_handled_malicious_input", False)
                    ]
                )

                logging.info(
                    "Completed fuzzing %s: %d successful, %d exceptions, "
                    "%d server rejections out of %d runs",
                    protocol_type,
                    successful,
                    exceptions,
                    server_rejections,
                    runs_per_type,
                )

            except Exception as e:
                logging.error(f"Failed to fuzz protocol type {protocol_type}: {e}")
                all_results[protocol_type] = [{"error": str(e)}]

        return all_results

    def generate_all_protocol_fuzz_cases(self) -> List[Dict[str, Any]]:
        """Generate a comprehensive set of fuzz cases for all MCP protocol types."""
        fuzz_cases = []

        # Generate multiple examples for each type
        for _ in range(5):  # 5 examples per type
            for protocol_type in [
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
            ]:
                try:
                    fuzzer_method = self.strategies.get_protocol_fuzzer_method(
                        protocol_type
                    )
                    if fuzzer_method:
                        data = fuzzer_method()
                        fuzz_cases.append({"type": protocol_type, "data": data})
                except Exception as e:
                    logging.warning(
                        f"Error generating fuzz case for {protocol_type}: {e}"
                    )

        return fuzz_cases
