#!/usr/bin/env python3
"""Semantic payload selection for fuzzing based on field names."""

from __future__ import annotations

import random
import re

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


class SemanticPayloadSelector:
    """Select payloads based on normalized token matching."""

    def __init__(self, rng: random.Random | None = None):
        self._rng = rng or random.Random()

    @staticmethod
    def _tokenize(key: str) -> set[str]:
        if not key:
            return set()
        # Normalize camelCase to tokens, then split on non-alnum.
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
        tokens = re.split(r"[^a-zA-Z0-9]+", normalized.lower())
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

        if tokens & {"uri", "url", "href", "link"}:
            payload = self._rng.choice(SSRF_PAYLOADS)
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"path", "file", "dir", "folder"}:
            payload = get_payload_within_length(
                max_length if max_length is not None else 100, "path"
            )
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"query", "search", "sql", "filter"}:
            payload = get_payload_within_length(
                max_length if max_length is not None else 100, "sql"
            )
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"html", "content", "body", "text"}:
            payload = get_payload_within_length(
                max_length if max_length is not None else 100, "xss"
            )
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"cmd", "command", "exec", "shell"}:
            payload = self._rng.choice(COMMAND_INJECTION)
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"id", "name", "key", "cursor"}:
            payload = inject_unicode_trick("test_id", max_length)
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"encoding", "escape"}:
            payload = self._rng.choice(ENCODING_BYPASS)
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )
        if tokens & {"type", "cast"}:
            payload = self._rng.choice(TYPE_CONFUSION)
            return fit_to_constraints(
                payload, min_length=min_length, max_length=max_length, mode=mode
            )

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

        if tokens & {"min", "lower", "start"}:
            if minimum is not None:
                return minimum - 1
            return -1
        if tokens & {"max", "upper", "limit", "size", "count", "timeout"}:
            if maximum is not None:
                return maximum + 1
            return 2147483648

        if maximum is not None:
            return maximum + 1
        if minimum is not None:
            return minimum - 1
        return 2147483648
