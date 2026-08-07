#!/usr/bin/env python3
"""Semantic payload selection for fuzzing based on field names."""

from __future__ import annotations

import random
import re
from typing import Any

from .interesting_values import (
    COMMAND_INJECTION,
    ENCODING_BYPASS,
    SQL_INJECTION,
    SSRF_PAYLOADS,
    TYPE_CONFUSION,
    get_payload_within_length,
    inject_unicode_trick,
)
from .utils import ConstraintMode, fit_to_constraints

# Compiled once: _tokenize runs for every fuzzed argument key.
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]+")

_DEFAULT_MAX_LENGTH = 100


def _payload_of(category: str):
    """Picker drawing a length-aware payload from ``category``."""

    def pick(_rng: random.Random, max_length: int | None) -> str:
        return get_payload_within_length(
            max_length if max_length is not None else _DEFAULT_MAX_LENGTH, category
        )

    return pick


def _choice_of(pool: list[str]):
    """Picker drawing uniformly from a fixed payload pool."""

    def pick(rng: random.Random, _max_length: int | None) -> str:
        return rng.choice(pool)

    return pick


# Token set -> payload picker, evaluated in order; first hit wins. Hoisted to
# module scope so the set literals are not rebuilt on every pick_string call.
_STRING_HINTS: list[tuple[frozenset[str], Any]] = [
    (frozenset({"uri", "url", "href", "link"}), _choice_of(SSRF_PAYLOADS)),
    (frozenset({"path", "file", "dir", "folder"}), _payload_of("path")),
    (frozenset({"query", "search", "sql", "filter"}), _payload_of("sql")),
    (frozenset({"html", "content", "body", "text"}), _payload_of("xss")),
    (frozenset({"cmd", "command", "exec", "shell"}), _choice_of(COMMAND_INJECTION)),
    # Identifiers get a unicode trick rather than garbage. Note this picker
    # forwards max_length unchanged (including None) to inject_unicode_trick.
    (
        frozenset({"id", "name", "key", "cursor"}),
        lambda _rng, max_length: inject_unicode_trick("test_id", max_length),
    ),
    (frozenset({"encoding", "escape"}), _choice_of(ENCODING_BYPASS)),
    (frozenset({"type", "cast"}), _choice_of(TYPE_CONFUSION)),
]

_MIN_TOKENS = frozenset({"min", "lower", "start"})
_MAX_TOKENS = frozenset({"max", "upper", "limit", "size", "count", "timeout"})

_INT32_OVERFLOW = 2147483648


class SemanticPayloadSelector:
    """Select payloads based on normalized token matching."""

    def __init__(self, rng: random.Random | None = None):
        self._rng = rng or random.Random()

    @staticmethod
    def _tokenize(key: str) -> set[str]:
        if not key:
            return set()
        # Normalize camelCase to tokens, then split on non-alnum.
        normalized = _CAMEL_BOUNDARY.sub(r"\1 \2", key)
        tokens = _NON_ALNUM.split(normalized.lower())
        return {t for t in tokens if t}

    def pick_string(
        self,
        key: str,
        *,
        min_length: int | None = None,
        max_length: int | None = None,
        mode: ConstraintMode = ConstraintMode.ENFORCE,
    ) -> str:
        tokens = self._tokenize(key)

        payload = None
        for hint_tokens, pick in _STRING_HINTS:
            if tokens & hint_tokens:
                payload = pick(self._rng, max_length)
                break
        if payload is None:
            # Default: SQL injection payload (most common vulnerability)
            payload = self._rng.choice(SQL_INJECTION)

        return fit_to_constraints(
            payload, min_length=min_length, max_length=max_length, mode=mode
        )

    def pick_number(
        self,
        key: str,
        *,
        minimum: int | float | None = None,
        maximum: int | float | None = None,
    ) -> int | float:
        tokens = self._tokenize(key)

        if tokens & _MIN_TOKENS:
            if minimum is not None:
                return minimum - 1
            return -1
        if tokens & _MAX_TOKENS:
            if maximum is not None:
                return maximum + 1
            return _INT32_OVERFLOW

        if maximum is not None:
            return maximum + 1
        if minimum is not None:
            return minimum - 1
        return _INT32_OVERFLOW
