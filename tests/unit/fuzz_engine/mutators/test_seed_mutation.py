#!/usr/bin/env python3
"""
Unit tests for seed mutation helpers.
"""

from __future__ import annotations

import random

import pytest

from mcp_fuzzer.fuzz_engine.mutators import seed_mutation

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


class FakeRandom:
    """Deterministic RNG for testing mutation branches."""

    def __init__(
        self,
        random_values: list[float] | None = None,
        choice_values: list[object] | None = None,
        randrange_values: list[int] | None = None,
    ) -> None:
        self._random_values = list(random_values or [])
        self._choice_values = list(choice_values or [])
        self._randrange_values = list(randrange_values or [])

    def random(self) -> float:
        return self._random_values.pop(0) if self._random_values else 0.5

    def choice(self, seq):  # type: ignore[override]
        if self._choice_values:
            value = self._choice_values.pop(0)
            if isinstance(value, int):
                return seq[value]
            if value in seq:
                return value
        return seq[0]

    def randrange(self, n: int) -> int:
        return self._randrange_values.pop(0) if self._randrange_values else 0


def test_mutate_seed_payload_empty_seed():
    result = seed_mutation.mutate_seed_payload({}, rng=random.Random(0))
    assert result == {}


def test_mutate_seed_payload_non_empty():
    rng = FakeRandom(random_values=[0.2, 0.2, 0.05], choice_values=["key", "key"])
    result = seed_mutation.mutate_seed_payload({"key": True}, rng=rng, stack=2)
    assert "key" not in result


def test_mutate_mapping_deletes_key():
    rng = FakeRandom(random_values=[0.05], choice_values=["target"])
    mapping = {"target": 1, "other": 2}
    seed_mutation._mutate_mapping(mapping, rng, depth=0)
    assert "target" not in mapping


def test_mutate_mapping_adds_key():
    rng = FakeRandom(
        random_values=[0.2, 0.05],
        choice_values=["only", "b", "c", "fuzz"],
    )
    mapping = {"only": 1}
    seed_mutation._mutate_mapping(mapping, rng, depth=0)
    added_keys = [key for key in mapping if key.startswith("fuzz_")]
    assert len(added_keys) == 1
    value = mapping[added_keys[0]]
    assert value in ["", "fuzz", 0, -1, 1, True, False, None] or isinstance(
        value, str
    )


def test_mutate_mapping_mutates_value():
    rng = FakeRandom(random_values=[0.2, 0.2], choice_values=["key"])
    mapping = {"key": False}
    seed_mutation._mutate_mapping(mapping, rng, depth=0)
    assert mapping["key"] is True


def test_mutate_list_pop_branch():
    rng = FakeRandom(random_values=[0.1], randrange_values=[0])
    values = [1, 2]
    result = seed_mutation._mutate_list(values, rng, depth=0)
    assert result == [2]


def test_mutate_list_append_branch():
    rng = FakeRandom(random_values=[0.3, 0.1], randrange_values=[0])
    values = [1]
    result = seed_mutation._mutate_list(values, rng, depth=0)
    assert len(result) == 2


def test_mutate_list_mutate_branch():
    rng = FakeRandom(random_values=[0.3, 0.3], randrange_values=[0])
    values = [True]
    result = seed_mutation._mutate_list(values, rng, depth=0)
    assert result == [False]


def test_mutate_value_depth_limit():
    rng = FakeRandom()
    assert seed_mutation._mutate_value("keep", rng, depth=4) == "keep"


def test_mutate_value_dict_and_unknown():
    rng = FakeRandom(random_values=[0.05], choice_values=["key"])
    value = {"key": "value"}
    seed_mutation._mutate_value(value, rng, depth=0)
    assert "key" not in value

    unknown = object()
    rng = FakeRandom(choice_values=[None])
    result = seed_mutation._mutate_value(unknown, rng, depth=0)
    assert result in ["", "fuzz", 0, -1, 1, True, False, None] or isinstance(
        result, str
    )


def test_mutate_value_scalar_types():
    rng = FakeRandom()
    assert seed_mutation._mutate_value(True, rng, depth=0) is False

    rng = FakeRandom(choice_values=[2])
    assert seed_mutation._mutate_value(10, rng, depth=0) == 26

    rng = FakeRandom(choice_values=[-1.0])
    assert seed_mutation._mutate_value(1.0, rng, depth=0) == 0.0


def test_mutate_str_variants():
    rng = FakeRandom(choice_values=[0, "!"])
    assert seed_mutation._mutate_str("abc", rng).endswith("!")

    rng = FakeRandom(choice_values=[1, seed_mutation._PAYLOADS[0]])
    result = seed_mutation._mutate_str("abc", rng)
    assert result.startswith(seed_mutation._PAYLOADS[0][:1])

    rng = FakeRandom(choice_values=[2])
    assert seed_mutation._mutate_str("abc", rng) == "cba"

    rng = FakeRandom(choice_values=[3])
    assert seed_mutation._mutate_str("Abc", rng) == "ABC"

    rng = FakeRandom(choice_values=[4])
    assert seed_mutation._mutate_str("AbC", rng) == "abc"

    rng = FakeRandom(choice_values=[5, "Z"])
    assert seed_mutation._mutate_str("abc", rng).endswith("Z")


def test_random_key_and_leaf():
    rng = FakeRandom(choice_values=["a", "b", "fuzz"])
    assert seed_mutation._random_key(rng) == "fuzz_ab"
    value = seed_mutation._random_leaf(rng)
    assert value in ["", "fuzz", 0, -1, 1, True, False, None] or isinstance(
        value, str
    )
