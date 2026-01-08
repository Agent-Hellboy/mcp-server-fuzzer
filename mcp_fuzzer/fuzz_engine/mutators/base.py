#!/usr/bin/env python3
"""
Base Mutator Interface

This module defines the base interface for all mutators.
"""

from abc import ABC, abstractmethod
from typing import Any


class Mutator(ABC):
    """Base interface for all mutators."""

    @abstractmethod
    async def mutate(self, *args: Any, **kwargs: Any) -> Any:
        """
        Generate or mutate fuzzing inputs.

        Args:
            *args: Positional arguments specific to the mutator
            **kwargs: Keyword arguments specific to the mutator

        Returns:
            Mutated or generated fuzzing input
        """
        pass
