#!/usr/bin/env python3
"""
Seed mutation helpers for feedback-guided fuzzing.

Produces small, structured mutations without requiring a schema.
"""

from __future__ import annotations

import copy
import random
import string
from typing import Any

from .strategies.interesting_values import (
    COMMAND_INJECTION,
    PATH_TRAVERSAL,
    SQL_INJECTION,
    XSS_PAYLOADS,
)


_PAYLOADS = SQL_INJECTION + XSS_PAYLOADS + PATH_TRAVERSAL + COMMAND_INJECTION


def mutate_seed_payload(
    seed: dict[str, Any],
    rng: random.Random | None = None,
    stack: int = 1,
) -> dict[str, Any]:
    """Return a mutated copy of the provided seed mapping."""
    rng = rng or random.Random()
    mutated = copy.deepcopy(seed)
    if not mutated:
        return mutated
    stack = max(1, stack)
    for _ in range(stack):
        _mutate_mapping(mutated, rng, depth=0)
    return mutated


def _mutate_mapping(mapping: dict[str, Any], rng: random.Random, depth: int) -> None:
    if not mapping:
        return
    keys = list(mapping.keys())
    target_key = rng.choice(keys)
    if rng.random() < 0.1:
        mapping.pop(target_key, None)
        return
    if rng.random() < 0.1:
        mapping[_random_key(rng)] = _random_leaf(rng)
        return
    mapping[target_key] = _mutate_value(mapping.get(target_key), rng, depth + 1)


def _mutate_list(values: list[Any], rng: random.Random, depth: int) -> list[Any]:
    if not values:
        return values
    mutated = list(values)
    idx = rng.randrange(len(mutated))
    if rng.random() < 0.2 and len(mutated) > 1:
        mutated.pop(idx)
        return mutated
    if rng.random() < 0.2:
        mutated.append(_random_leaf(rng))
        return mutated
    mutated[idx] = _mutate_value(mutated[idx], rng, depth + 1)
    return mutated


def _mutate_value(value: Any, rng: random.Random, depth: int) -> Any:
    if depth > 3:
        return value
    if isinstance(value, dict):
        _mutate_mapping(value, rng, depth)
        return value
    if isinstance(value, list):
        return _mutate_list(value, rng, depth)
    if isinstance(value, bool):
        return not value
    if isinstance(value, int) and not isinstance(value, bool):
        return _mutate_int(value, rng)
    if isinstance(value, float):
        return value + rng.choice([-1.0, 1.0, 10.0])
    if isinstance(value, str):
        return _mutate_str(value, rng)
    return _random_leaf(rng)


def _mutate_int(value: int, rng: random.Random) -> int:
    choices = [value + 1, value - 1, value + 16, value - 16, 0, -1, 2**31 - 1]
    return rng.choice(choices)


def _mutate_str(value: str, rng: random.Random) -> str:
    mutations = [
        lambda v: v + rng.choice(["!", "?", "/../", "\\..\\", "'\""]),
        lambda v: rng.choice(_PAYLOADS)[: max(1, len(v))],
        lambda v: v[::-1],
        lambda v: v.upper(),
        lambda v: v.lower(),
        lambda v: v + rng.choice(string.ascii_letters),
    ]
    return rng.choice(mutations)(value)


def _random_key(rng: random.Random) -> str:
    return (
        "fuzz_"
        + rng.choice(string.ascii_lowercase)
        + rng.choice(string.ascii_lowercase)
    )


def _random_leaf(rng: random.Random) -> Any:
    options: list[Any] = [
        "",
        "fuzz",
        rng.choice(_PAYLOADS),
        0,
        -1,
        1,
        True,
        False,
        None,
    ]
    return rng.choice(options)
