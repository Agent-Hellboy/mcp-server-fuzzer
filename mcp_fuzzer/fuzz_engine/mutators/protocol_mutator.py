#!/usr/bin/env python3
"""
Protocol Mutator

This module contains the mutation logic for generating fuzzed protocol messages.
"""

import copy
import inspect
import random
from pathlib import Path
from typing import Any, Callable

from .base import Mutator
from .strategies import ProtocolStrategies
from .seed_pool import SeedPool
from .seed_mutation import mutate_seed_payload
from .utils import havoc_stack


class ProtocolMutator(Mutator):
    """Generates fuzzed protocol messages."""

    def __init__(
        self,
        seed_pool: SeedPool | None = None,
        corpus_dir: Path | None = None,
        havoc_mode: bool = False,
        havoc_min: int = 2,
        havoc_max: int = 6,
    ):
        """Initialize the protocol mutator."""
        self.strategies = ProtocolStrategies()
        storage_dir = corpus_dir / "protocol" if corpus_dir else None
        if seed_pool:
            self.seed_pool = seed_pool
            self._rng = getattr(seed_pool, "_rng", random.Random())
        else:
            rng = random.Random()
            self.seed_pool = SeedPool(
                max_per_key=40,
                reseed_ratio=0.3,
                storage_dir=storage_dir,
                rng=rng,
            )
            self._rng = rng
        self.havoc_mode = havoc_mode
        self.havoc_min = havoc_min
        self.havoc_max = havoc_max

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
        if self.seed_pool.should_reseed(self._seed_ratio_for_phase(phase)):
            seed = self.seed_pool.pick_seed(protocol_type)
            if isinstance(seed, dict):
                return self._mutate_from_seed(protocol_type, seed, phase)

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
        return maybe_coro

    def record_feedback(
        self,
        protocol_type: str,
        fuzz_data: dict[str, Any],
        *,
        server_error: str | None = None,
        spec_checks: list[dict[str, Any]] | None = None,
        response_signature: str | None = None,
    ) -> None:
        if not isinstance(fuzz_data, dict):
            return
        seed = copy.deepcopy(fuzz_data)
        signature = _protocol_signature(server_error, spec_checks)
        if signature:
            self.seed_pool.add_seed(protocol_type, seed, signature=signature, score=1.4)
        if response_signature:
            self.seed_pool.add_seed(
                protocol_type,
                seed,
                signature=f"resp:{response_signature}",
                score=1.2,
            )

    @staticmethod
    def _seed_ratio_for_phase(phase: str) -> float:
        return 0.1 if phase == "realistic" else 0.3

    def _mutate_from_seed(
        self,
        protocol_type: str,
        seed: dict[str, Any],
        phase: str,
    ) -> dict[str, Any]:
        stack = self._havoc_stack()
        mutated = mutate_seed_payload(seed, stack=stack)
        if "jsonrpc" in mutated:
            mutated["jsonrpc"] = "2.0"
        if "method" not in mutated:
            fuzzer_method = self.get_fuzzer_method(protocol_type, phase)
            if fuzzer_method and not inspect.iscoroutinefunction(fuzzer_method):
                base = fuzzer_method()
                if inspect.isawaitable(base):
                    base = None
                if isinstance(base, dict) and base.get("method"):
                    mutated["method"] = base["method"]
        return mutated

    def _havoc_stack(self) -> int:
        return havoc_stack(
            havoc_mode=self.havoc_mode,
            havoc_min=self.havoc_min,
            havoc_max=self.havoc_max,
            rng=self._rng,
        )


def _protocol_signature(
    server_error: str | None,
    spec_checks: list[dict[str, Any]] | None,
) -> str | None:
    if server_error:
        return f"err:{server_error[:120]}"
    if spec_checks:
        failures = []
        for check in spec_checks:
            if str(check.get("status", "")).upper() == "FAIL":
                check_id = check.get("id")
                if check_id is not None:
                    failures.append(str(check_id))
        if failures:
            return "spec:" + ",".join(sorted(set(failures)))
    return None
