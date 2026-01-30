import random

from mcp_fuzzer.fuzz_engine.mutators.utils import havoc_stack


def test_havoc_stack_disabled_returns_one():
    assert havoc_stack(havoc_mode=False, havoc_min=2, havoc_max=6) == 1


def test_havoc_stack_normalizes_bounds():
    rng = random.Random(0)

    assert havoc_stack(havoc_mode=True, havoc_min=0, havoc_max=0, rng=rng) == 1


def test_havoc_stack_uses_rng():
    rng = random.Random(0)

    assert havoc_stack(havoc_mode=True, havoc_min=2, havoc_max=4, rng=rng) == 3


def test_havoc_stack_inverted_bounds():
    rng = random.Random(0)

    assert havoc_stack(havoc_mode=True, havoc_min=5, havoc_max=3, rng=rng) == 5
