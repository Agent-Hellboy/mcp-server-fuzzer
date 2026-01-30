#!/usr/bin/env python3
"""
Fuzzer Context

Lightweight container for per-run fuzzing context to avoid module-level state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import random
from typing import Any


@dataclass(frozen=True)
class FuzzerContext:
    """
    Context for deterministic, schema-aware fuzzing.

    Notes on concurrency:
    - This object is immutable; pass a distinct instance per run.
    - If you need deterministic behavior across threads, inject a seeded rng
      and explicit run_index from the caller.
    """

    phase: str = "aggressive"
    schema: dict[str, Any] | None = None
    key: str | None = None
    run_index: int | None = None
    rng: random.Random | None = None
    corpus_dir: Path | None = None
    havoc_mode: bool = False
    havoc_min: int = 2
    havoc_max: int = 6

    def with_defaults(self) -> "FuzzerContext":
        rng = self.rng or random.Random()
        run_index = (
            self.run_index if self.run_index is not None else rng.randint(0, 1_000_000)
        )
        return replace(self, rng=rng, run_index=run_index)


def ensure_context(
    context: FuzzerContext | None,
    *,
    phase: str,
    schema: dict[str, Any] | None = None,
    key: str | None = None,
    run_index: int | None = None,
    rng: random.Random | None = None,
    corpus_dir: Path | None = None,
    havoc_mode: bool | None = None,
    havoc_min: int | None = None,
    havoc_max: int | None = None,
) -> FuzzerContext:
    """Create or normalize a FuzzerContext with safe defaults."""
    if context is None:
        context = FuzzerContext(
            phase=phase,
            schema=schema,
            key=key,
            run_index=run_index,
            rng=rng,
            corpus_dir=corpus_dir,
            havoc_mode=bool(havoc_mode) if havoc_mode is not None else False,
            havoc_min=havoc_min if havoc_min is not None else 2,
            havoc_max=havoc_max if havoc_max is not None else 6,
        )
    else:
        context = replace(
            context,
            phase=phase if phase is not None else context.phase,
            schema=schema if schema is not None else context.schema,
            key=key if key is not None else context.key,
            run_index=run_index if run_index is not None else context.run_index,
            rng=rng if rng is not None else context.rng,
            corpus_dir=corpus_dir if corpus_dir is not None else context.corpus_dir,
            havoc_mode=(
                bool(havoc_mode)
                if havoc_mode is not None
                else context.havoc_mode
            ),
            havoc_min=havoc_min if havoc_min is not None else context.havoc_min,
            havoc_max=havoc_max if havoc_max is not None else context.havoc_max,
        )
    return context.with_defaults()
