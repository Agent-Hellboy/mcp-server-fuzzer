#!/usr/bin/env python3
"""
Protocol Fuzzer

This module contains the orchestration logic for fuzzing MCP protocol types.
"""

import logging
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
        """Fuzz a specific protocol type with specified phase and analyze responses."""
        if runs <= 0:
            return []

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

                # Send the request to the server if transport is available
                server_response = None
                server_error = None

                if self.transport:
                    try:
                        # Send envelope exactly as generated
                        server_response = await self.transport.send_raw(fuzz_data)
                        logging.debug(
                            f"Server accepted fuzzed envelope for {protocol_type}"
                        )
                    except Exception as server_exception:
                        server_error = str(server_exception)
                        logging.debug(
                            "Server rejected fuzzed envelope: %s", server_exception
                        )

                # Create the result entry
                result = {
                    "protocol_type": protocol_type,
                    "run": i + 1,
                    "fuzz_data": fuzz_data,
                    "success": True,
                    "server_response": server_response,
                    "server_error": server_error,
                    "server_handled_malicious_input": server_error is not None,  # Good
                }

                results.append(result)

                logging.debug(f"Fuzzed {protocol_type} run {i + 1}/{runs}")

            except Exception as e:
                logging.error(f"Error fuzzing {protocol_type} run {i + 1}: {e}")
                results.append(
                    {
                        "protocol_type": protocol_type,
                        "run": i + 1,
                        "fuzz_data": None,
                        "success": False,
                        "exception": str(e),
                    }
                )

        return results

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

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5, phase: str = "aggressive"
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz all known protocol types."""
        if runs_per_type <= 0:
            return {}

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
                logging.info(
                    f"Completed {protocol_type}: {successful}/{total} successful, "
                    f"{server_rejections} server rejections"
                )

            except Exception as e:
                logging.error(f"Failed to fuzz {protocol_type}: {e}")
                all_results[protocol_type] = []

        return all_results
