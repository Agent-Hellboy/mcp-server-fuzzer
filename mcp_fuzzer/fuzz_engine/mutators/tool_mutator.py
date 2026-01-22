#!/usr/bin/env python3
"""
Tool Mutator

This module contains the mutation logic for generating fuzzed tool arguments.
"""

import random
from pathlib import Path
from typing import Any
import copy

from .base import Mutator
from .strategies import ToolStrategies
from .seed_pool import SeedPool
from .seed_mutation import mutate_seed_payload


class ToolMutator(Mutator):
    """Generates fuzzed tool arguments."""

    def __init__(
        self,
        seed_pool: SeedPool | None = None,
        corpus_dir: Path | None = None,
        havoc_mode: bool = False,
        havoc_min: int = 2,
        havoc_max: int = 6,
    ):
        """Initialize the tool mutator."""
        self.strategies = ToolStrategies()
        storage_dir = corpus_dir / "tools" if corpus_dir else None
        self.seed_pool = seed_pool or SeedPool(
            max_per_key=50, reseed_ratio=0.35, storage_dir=storage_dir
        )
        self.havoc_mode = havoc_mode
        self.havoc_min = havoc_min
        self.havoc_max = havoc_max

    async def mutate(
        self, tool: dict[str, Any], phase: str = "aggressive"
    ) -> dict[str, Any]:
        """
        Generate fuzzed arguments for a tool.

        Args:
            tool: Tool definition
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            Dictionary of fuzzed tool arguments
        """
        tool_name = tool.get("name", "unknown")
        if self.seed_pool.should_reseed(self._seed_ratio_for_phase(phase)):
            seed = self.seed_pool.pick_seed(tool_name)
            if isinstance(seed, dict):
                stack = self._havoc_stack()
                return mutate_seed_payload(seed, stack=stack)
        return await self.strategies.fuzz_tool_arguments(tool, phase=phase)

    def record_feedback(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        exception: str | None = None,
        spec_checks: list[dict[str, Any]] | None = None,
        response_signature: str | None = None,
    ) -> None:
        """Record interesting arguments for future mutation."""
        if not isinstance(args, dict):
            return
        seed = copy.deepcopy(args)
        signature = _tool_signature(exception, spec_checks)
        if signature:
            self.seed_pool.add_seed(tool_name, seed, signature=signature, score=1.5)
        if response_signature:
            self.seed_pool.add_seed(
                tool_name, seed, signature=f"resp:{response_signature}", score=1.2
            )

    @staticmethod
    def _seed_ratio_for_phase(phase: str) -> float:
        return 0.15 if phase == "realistic" else 0.35

    def _havoc_stack(self) -> int:
        if not self.havoc_mode:
            return 1
        low = max(1, self.havoc_min)
        high = max(low, self.havoc_max)
        return random.randint(low, high)


def _tool_signature(
    exception: str | None,
    spec_checks: list[dict[str, Any]] | None,
) -> str | None:
    if exception:
        return f"exc:{exception[:120]}"
    if spec_checks:
        failures = [
            check.get("id")
            for check in spec_checks
            if str(check.get("status", "")).upper() == "FAIL"
        ]
        if failures:
            return "spec:" + ",".join(sorted(set(failures)))
    return None
