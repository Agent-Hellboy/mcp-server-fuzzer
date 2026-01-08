#!/usr/bin/env python3
"""
Protocol Mutator

This module contains the mutation logic for generating fuzzed protocol messages.
"""

import inspect
from typing import Any, Callable

from .base import Mutator
from .strategies import ProtocolStrategies


class ProtocolMutator(Mutator):
    """Generates fuzzed protocol messages."""

    def __init__(self):
        """Initialize the protocol mutator."""
        self.strategies = ProtocolStrategies()

    def get_fuzzer_method(
        self, protocol_type: str, phase: str = "aggressive"
    ) -> Callable[..., dict[str, Any] | None]:
        """
        Get the appropriate fuzzer method for a protocol type and phase.

        Args:
            protocol_type: Protocol type to get fuzzer method for
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Fuzzer method or None if not found
        """
        return self.strategies.get_protocol_fuzzer_method(protocol_type, phase)

    async def mutate(
        self,
        protocol_type: str,
        phase: str = "aggressive",
    ) -> dict[str, Any]:
        """
        Generate fuzzed data for a protocol type.

        Args:
            protocol_type: Protocol type to fuzz
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Generated fuzz data
        """
        fuzzer_method = self.get_fuzzer_method(protocol_type, phase)
        if not fuzzer_method:
            raise ValueError(
                f"Unknown protocol type: {protocol_type} for phase: {phase}"
            )

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
