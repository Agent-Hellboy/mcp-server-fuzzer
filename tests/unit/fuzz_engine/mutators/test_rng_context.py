#!/usr/bin/env python3
"""Tests for shared fuzz RNG context."""

from __future__ import annotations

import random

from mcp_fuzzer.fuzz_engine.mutators.rng_context import (
    fuzz_rng_scope,
    get_fuzz_rng,
    lazy_rng,
)


def test_fuzz_rng_scope_binds_seeded_generator():
    seeded_a = random.Random(7)
    seeded_b = random.Random(7)
    with fuzz_rng_scope(seeded_a):
        first = [get_fuzz_rng().random() for _ in range(5)]
    with fuzz_rng_scope(seeded_b):
        second = [get_fuzz_rng().random() for _ in range(5)]
    assert first == second


def test_lazy_rng_delegates_to_active_rng():
    seeded = random.Random(99)
    with fuzz_rng_scope(seeded):
        assert lazy_rng.randint(1, 1) == 1
        assert isinstance(lazy_rng.choice([1, 2, 3]), int)


def test_get_fuzz_rng_without_scope_returns_random_instance():
    rng = get_fuzz_rng()
    assert isinstance(rng, random.Random)
