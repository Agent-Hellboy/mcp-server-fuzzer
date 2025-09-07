#!/usr/bin/env python3
"""
Strategy Manager

This module provides a unified interface for managing fuzzing strategies.
It handles the dispatch between realistic and aggressive phases.
"""

from typing import Any, Dict, List, Optional, Callable
import random

from .realistic import (
    fuzz_tool_arguments_realistic,
    fuzz_initialize_request_realistic,
    fuzz_list_resources_request_realistic,
    fuzz_read_resource_request_realistic,
    fuzz_subscribe_request_realistic,
    fuzz_unsubscribe_request_realistic,
    fuzz_list_prompts_request_realistic,
    fuzz_get_prompt_request_realistic,
    fuzz_list_roots_request_realistic,
    fuzz_set_level_request_realistic,
    fuzz_complete_request_realistic,
)
from .aggressive import (
    fuzz_tool_arguments_aggressive,
    fuzz_initialize_request_aggressive,
    get_protocol_fuzzer_method as get_aggressive_fuzzer_method,
)


class ProtocolStrategies:
    """Unified protocol strategies with two-phase approach."""

    REALISTIC_PHASE = "realistic"
    AGGRESSIVE_PHASE = "aggressive"

    # Mapping of protocol types to their realistic and aggressive strategy functions
    PROTOCOL_STRATEGIES = {
        "InitializeRequest": {
            "realistic": fuzz_initialize_request_realistic,
            "aggressive": fuzz_initialize_request_aggressive,
        },
        "ListResourcesRequest": {
            "realistic": fuzz_list_resources_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("ListResourcesRequest"),
        },
        "ReadResourceRequest": {
            "realistic": fuzz_read_resource_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("ReadResourceRequest"),
        },
        "SubscribeRequest": {
            "realistic": fuzz_subscribe_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("SubscribeRequest"),
        },
        "UnsubscribeRequest": {
            "realistic": fuzz_unsubscribe_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("UnsubscribeRequest"),
        },
        "ListPromptsRequest": {
            "realistic": fuzz_list_prompts_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("ListPromptsRequest"),
        },
        "GetPromptRequest": {
            "realistic": fuzz_get_prompt_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("GetPromptRequest"),
        },
        "ListRootsRequest": {
            "realistic": fuzz_list_roots_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("ListRootsRequest"),
        },
        "SetLevelRequest": {
            "realistic": fuzz_set_level_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("SetLevelRequest"),
        },
        "CompleteRequest": {
            "realistic": fuzz_complete_request_realistic,
            "aggressive": get_aggressive_fuzzer_method("CompleteRequest"),
        },
    }

    @staticmethod
    def get_protocol_fuzzer_method(
        protocol_type: str,
        phase: str = "aggressive",
    ) -> Optional[Callable[[], Dict[str, Any]]]:
        """
        Get the fuzzer method for a specific protocol type and phase.

        Args:
            protocol_type: The protocol type to get the fuzzer for
            phase: The fuzzing phase (realistic or aggressive)

        Returns:
            Fuzzer method or None if not found
        """
        if protocol_type in ProtocolStrategies.PROTOCOL_STRATEGIES:
            strategy_config = ProtocolStrategies.PROTOCOL_STRATEGIES[protocol_type]
            if phase in strategy_config:
                return strategy_config[phase]

        # Fallback to aggressive strategies for any remaining protocol types
        return get_aggressive_fuzzer_method(protocol_type)

    @staticmethod
    def generate_batch_request(
        protocol_types: Optional[List[str]] = None,
        phase: str = "aggressive",
        min_batch_size: int = 2,
        max_batch_size: int = 5,
        include_notifications: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Generate a batch of JSON-RPC requests/notifications.

        Args:
            protocol_types: List of protocol types to include (None for random
                           selection)
            phase: Fuzzing phase (realistic or aggressive)
            min_batch_size: Minimum number of requests in batch
            max_batch_size: Maximum number of requests in batch
            include_notifications: Whether to include notifications (no ID)

        Returns:
            List of JSON-RPC requests/notifications forming a batch
        """
        if protocol_types is None:
            # Default protocol types for batching
            protocol_types = [
                "InitializeRequest",
                "ListResourcesRequest",
                "ReadResourceRequest",
                "ListPromptsRequest",
                "GetPromptRequest",
                "ListRootsRequest",
                "SetLevelRequest",
                "CompleteRequest",
                "ListResourceTemplatesRequest",
                "ElicitRequest",
                "PingRequest",
                "SubscribeRequest",
                "UnsubscribeRequest",
                "CreateMessageRequest",
            ]

        if min_batch_size > max_batch_size:
            min_batch_size, max_batch_size = max_batch_size, min_batch_size
        batch_size = random.randint(min_batch_size, max_batch_size)
        batch = []

        for i in range(batch_size):
            # Randomly select protocol type
            protocol_type = random.choice(protocol_types)

            # Get the fuzzer method for this type and phase
            fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method(
                protocol_type, phase
            )
            if not fuzzer_method:
                continue

            # Generate the request
            request = fuzzer_method()

            # Sometimes make it a notification (no ID) if enabled
            if include_notifications and random.random() < 0.3:
                request.pop("id", None)

            # Add some ID edge cases occasionally
            if "id" in request and random.random() < 0.2:
                # Edge case IDs
                edge_cases = [
                    None,  # Valid for notifications
                    "",  # Empty string
                    0,  # Zero
                    -1,  # Negative
                    "duplicate_id",  # Same ID as another in batch
                    float("inf"),  # Infinity
                    {"nested": "object"},  # Object as ID
                ]
                request["id"] = random.choice(edge_cases)

            batch.append(request)

        # Ensure we have at least one request with ID for responses
        if batch and not any(
            "id" in req and req.get("id") is not None for req in batch
        ):
            # Add an ID to the first request
            if batch:
                batch[0]["id"] = random.randint(1, 1000)

        return batch

    @staticmethod
    def fuzz_initialize_request(phase: str = "aggressive") -> Dict[str, Any]:
        """
        Generate a fuzzed initialize request.

        Args:
            phase: The fuzzing phase to use (defaults to aggressive)

        Returns:
            Fuzzed initialize request dictionary
        """
        strategies = ProtocolStrategies
        method = strategies.get_protocol_fuzzer_method("InitializeRequest", phase)
        if method:
            return method()
        else:
            # Fallback to aggressive if method not found
            return fuzz_initialize_request_aggressive()

    @staticmethod
    def generate_out_of_order_batch(
        protocol_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate a batch with deliberately out-of-order IDs to test server handling.

        Args:
            protocol_types: List of protocol types to include

        Returns:
            Batch with non-sequential or duplicate IDs
        """
        batch = ProtocolStrategies.generate_batch_request(
            protocol_types, max_batch_size=3, include_notifications=False
        )

        # Assign non-sequential IDs
        ids = [5, 1, 3, 2, 1]  # Out of order with duplicate
        for i, request in enumerate(batch):
            if "id" in request:
                request["id"] = ids[i % len(ids)]

        return batch


class ToolStrategies:
    """Unified tool strategies with two-phase approach."""

    REALISTIC_PHASE = "realistic"
    AGGRESSIVE_PHASE = "aggressive"

    @staticmethod
    async def fuzz_tool_arguments(
        tool: Dict[str, Any], phase: str = "aggressive"
    ) -> Dict[str, Any]:
        """Generate fuzzed tool arguments based on phase."""
        if phase == ToolStrategies.REALISTIC_PHASE:
            return await fuzz_tool_arguments_realistic(tool)
        else:
            return fuzz_tool_arguments_aggressive(tool)
