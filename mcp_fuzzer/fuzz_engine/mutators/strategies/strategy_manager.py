#!/usr/bin/env python3
"""
Strategy Manager

This module provides a unified interface for managing fuzzing strategies.
It handles the dispatch between realistic and aggressive phases.
"""

from typing import Any, Callable
import random

from .realistic import fuzz_tool_arguments_realistic
from .aggressive import fuzz_tool_arguments_aggressive
from .spec_protocol import get_spec_protocol_fuzzer_method
from .registry import strategy_registry


class ProtocolStrategies:
    """Unified protocol strategies with two-phase approach."""

    REALISTIC_PHASE = "realistic"
    AGGRESSIVE_PHASE = "aggressive"
    DEFAULT_PROTOCOL_TYPES = (
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
    )

    @staticmethod
    def get_protocol_fuzzer_method(
        protocol_type: str,
        phase: str = "aggressive",
    ) -> Callable[[], dict[str, Any] | None] | None:
        """Get the fuzzer method for a protocol type and phase using spec_protocol."""
        override = strategy_registry.get_protocol(protocol_type, phase)
        if override:
            return override
        return get_spec_protocol_fuzzer_method(protocol_type, phase)

    @staticmethod
    def generate_batch_request(
        protocol_types: list[str] | None = None,
        phase: str = "aggressive",
        min_batch_size: int = 2,
        max_batch_size: int = 5,
        include_notifications: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate a batch of JSON-RPC requests/notifications."""
        if protocol_types is None:
            protocol_types = list(ProtocolStrategies.DEFAULT_PROTOCOL_TYPES)

        if not protocol_types:
            return []

        if min_batch_size > max_batch_size:
            min_batch_size, max_batch_size = max_batch_size, min_batch_size

        batch_size = random.randint(min_batch_size, max_batch_size)
        batch = []

        for _ in range(batch_size):
            protocol_type = random.choice(protocol_types)
            fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method(
                protocol_type, phase
            )
            if not fuzzer_method:
                continue

            request = fuzzer_method()
            if not request:
                continue

            if include_notifications and random.random() < 0.3:
                request.pop("id", None)

            if "id" in request and random.random() < 0.2:
                edge_cases = [
                    None, "", 0, -1, "duplicate_id", float("inf"), {"nested": "object"},
                ]
                request["id"] = random.choice(edge_cases)

            batch.append(request)

        if batch and not any(
            "id" in req and req.get("id") is not None for req in batch
        ):
            batch[0]["id"] = random.randint(1, 1000)

        return batch

    @staticmethod
    def fuzz_initialize_request(phase: str = "aggressive") -> dict[str, Any] | None:
        """Generate a fuzzed initialize request."""
        method = ProtocolStrategies.get_protocol_fuzzer_method(
            "InitializeRequest", phase
        )
        return method() if method else None

    @staticmethod
    def generate_out_of_order_batch(
        protocol_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate a batch with deliberately out-of-order IDs
        to test server handling."""
        batch = ProtocolStrategies.generate_batch_request(
            protocol_types, max_batch_size=3, include_notifications=False
        )

        ids = [5, 1, 3, 2, 1]
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
        tool: dict[str, Any], phase: str = "aggressive"
    ) -> dict[str, Any]:
        """Generate fuzzed tool arguments based on phase."""
        override = strategy_registry.get_tool(phase)
        if override:
            return await override(tool)
        if phase == ToolStrategies.REALISTIC_PHASE:
            return await fuzz_tool_arguments_realistic(tool)
        return fuzz_tool_arguments_aggressive(tool)
