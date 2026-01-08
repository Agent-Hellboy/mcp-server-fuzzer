#!/usr/bin/env python3
"""
Batch Mutator

This module contains the mutation logic for generating batch requests.
"""

from typing import Any

from .base import Mutator
from .strategies import ProtocolStrategies


class BatchMutator(Mutator):
    """Generates fuzzed batch requests."""

    def __init__(self):
        """Initialize the batch mutator."""
        self.strategies = ProtocolStrategies()

    async def mutate(
        self,
        protocol_types: list[str] | None = None,
        phase: str = "aggressive",
    ) -> list[dict[str, Any]] | None:
        """
        Generate a batch request with mixed protocol types.

        Args:
            protocol_types: List of protocol types to include in batches
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Generated batch request or None if generation fails
        """
        return self.strategies.generate_batch_request(
            protocol_types=protocol_types, phase=phase
        )
