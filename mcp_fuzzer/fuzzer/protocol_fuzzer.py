#!/usr/bin/env python3
"""
Protocol Fuzzer

This module contains the orchestration logic for fuzzing MCP protocol types.
"""

import json
import logging
from typing import Any, Dict, List

from ..strategy import ProtocolStrategies


class ProtocolFuzzer:
    """Orchestrates fuzzing of MCP protocol types."""

    def __init__(self):
        self.strategies = ProtocolStrategies()
        self.request_id_counter = 0

    def _get_request_id(self) -> int:
        """Generate a request ID for JSON-RPC requests."""
        self.request_id_counter += 1
        return self.request_id_counter

    def fuzz_protocol_type(
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

                results.append(
                    {
                        "protocol_type": protocol_type,
                        "run": i + 1,
                        "fuzz_data": fuzz_data,
                        "success": True,
                    }
                )

            except Exception as e:
                logging.warning(f"Exception during fuzzing {protocol_type}: {e}")
                results.append(
                    {
                        "protocol_type": protocol_type,
                        "run": i + 1,
                        "fuzz_data": fuzz_data if "fuzz_data" in locals() else None,
                        "exception": str(e),
                        "success": False,
                    }
                )

        return results

    def fuzz_protocol_type_both_phases(
        self, protocol_type: str, runs_per_phase: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz a protocol type in both realistic and aggressive phases."""
        results = {}

        logging.info(f"Running two-phase fuzzing for {protocol_type}")

        # Phase 1: Realistic fuzzing
        logging.info(f"Phase 1: Realistic fuzzing for {protocol_type}")
        results["realistic"] = self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        logging.info(f"Phase 2: Aggressive fuzzing for {protocol_type}")
        results["aggressive"] = self.fuzz_protocol_type(
            protocol_type, runs=runs_per_phase, phase="aggressive"
        )

        return results

    def fuzz_all_protocol_types(
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
                results = self.fuzz_protocol_type(protocol_type, runs_per_type, phase)
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
