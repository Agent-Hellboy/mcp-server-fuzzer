#!/usr/bin/env python3
"""Shared mutator utilities."""

from __future__ import annotations

import random


def havoc_stack(
    *,
    havoc_mode: bool,
    havoc_min: int,
    havoc_max: int,
    rng: random.Random | None = None,
) -> int:
    """Compute the mutation stack depth for havoc mode."""
    if not havoc_mode:
        return 1
    rng = rng or random.Random()
    low = max(1, havoc_min)
    high = max(low, havoc_max)
    return rng.randint(low, high)
