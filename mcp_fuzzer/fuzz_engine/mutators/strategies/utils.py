#!/usr/bin/env python3
"""Utilities for strategy implementations."""

from __future__ import annotations

from enum import Enum


class ConstraintMode(str, Enum):
    ENFORCE = "enforce"
    TRUNCATE = "truncate"
    VIOLATE = "violate"


def fit_to_constraints(
    value: str,
    *,
    min_length: int | None = None,
    max_length: int | None = None,
    mode: ConstraintMode = ConstraintMode.ENFORCE,
    pad_char: str = "a",
) -> str:
    """
    Fit a string to length constraints.

    Modes:
    - ENFORCE: pad/trim to ensure min/max are satisfied.
    - TRUNCATE: only trim if too long; never pad.
    - VIOLATE: intentionally violate by one if constraints exist.
    """
    if min_length is None:
        min_length = 0
    if max_length is not None and max_length < 0:
        max_length = 0

    if max_length == 0:
        return ""

    if mode == ConstraintMode.VIOLATE:
        if max_length is not None:
            return value + (pad_char * max(1, max_length + 1 - len(value)))
        if min_length > 0:
            return value[: max(0, min_length - 1)]
        return value + pad_char

    if max_length is not None and len(value) > max_length:
        value = value[:max_length]
    if mode == ConstraintMode.ENFORCE and len(value) < min_length:
        value = value + (pad_char * (min_length - len(value)))
    return value
