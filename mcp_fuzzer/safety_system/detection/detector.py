#!/usr/bin/env python3
"""
Pattern-based danger detection helpers for the safety system.

The original SafetyFilter implementation embedded pattern compilation and
matching logic directly inside the class.  Splitting the responsibilities
into this module gives us a single, well-typed place to maintain matching
rules, making it easier to extend or swap implementations (e.g. AC automata).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable, Iterator, Sequence


class DangerType(str, Enum):
    """Enumeration of dangerous content classes we know how to detect."""

    URL = "url"
    SCRIPT = "script"
    COMMAND = "command"


@dataclass(frozen=True)
class DangerMatch:
    """
    Lightweight record describing a dangerous match.

    Attributes:
        danger_type: The type of danger detected.
        pattern:     The regex pattern that matched (useful for debug logs).
        preview:     Short preview of the offending value for logs/telemetry.
    """

    danger_type: DangerType
    pattern: str
    preview: str


def _compile_patterns(patterns: Sequence[str | re.Pattern]) -> tuple[re.Pattern, ...]:
    """Compile all patterns with IGNORECASE, preserving already-compiled ones."""
    compiled: list[re.Pattern] = []
    for pattern in patterns:
        if isinstance(pattern, re.Pattern):
            compiled.append(pattern)
        else:
            compiled.append(re.compile(pattern, re.IGNORECASE))
    return tuple(compiled)


@dataclass(frozen=True)
class PatternRegistry:
    """Container for compiled patterns grouped by danger type."""

    url_patterns: tuple[re.Pattern, ...]
    script_patterns: tuple[re.Pattern, ...]
    command_patterns: tuple[re.Pattern, ...]

    @classmethod
    def from_sources(
        cls,
        url_patterns: Sequence[str | re.Pattern],
        script_patterns: Sequence[str | re.Pattern],
        command_patterns: Sequence[str | re.Pattern],
    ) -> "PatternRegistry":
        return cls(
            url_patterns=_compile_patterns(url_patterns),
            script_patterns=_compile_patterns(script_patterns),
            command_patterns=_compile_patterns(command_patterns),
        )

    def get(self, danger_type: DangerType) -> tuple[re.Pattern, ...]:
        mapping = {
            DangerType.URL: self.url_patterns,
            DangerType.SCRIPT: self.script_patterns,
            DangerType.COMMAND: self.command_patterns,
        }
        return mapping[danger_type]


class DangerDetector:
    """
    Shared engine for matching dangerous values.

    SafetyFilter relies on the detector to answer simple boolean queries as well
    as provide rich match metadata for logging and telemetry.
    """

    def __init__(
        self,
        url_patterns: Sequence[str | re.Pattern],
        script_patterns: Sequence[str | re.Pattern],
        command_patterns: Sequence[str | re.Pattern],
    ) -> None:
        self._registry = PatternRegistry.from_sources(
            url_patterns, script_patterns, command_patterns
        )

    # ----- Public accessors -------------------------------------------------
    @property
    def url_patterns(self) -> tuple[re.Pattern, ...]:
        return self._registry.url_patterns

    @property
    def script_patterns(self) -> tuple[re.Pattern, ...]:
        return self._registry.script_patterns

    @property
    def command_patterns(self) -> tuple[re.Pattern, ...]:
        return self._registry.command_patterns

    # ----- Matching helpers -------------------------------------------------
    def contains(self, value: str | None, danger_type: DangerType) -> bool:
        """Return True if value contains the requested danger type."""
        if not value:
            return False
        return any(pattern.search(value) for pattern in self._registry.get(danger_type))

    def first_match(
        self,
        value: str | None,
        danger_types: Iterable[DangerType] | None = None,
    ) -> DangerMatch | None:
        """Return the first matching danger across the provided types."""
        if not value:
            return None

        types_to_search = tuple(danger_types) if danger_types else tuple(DangerType)
        for danger_type in types_to_search:
            for pattern in self._registry.get(danger_type):
                if pattern.search(value):
                    return DangerMatch(
                        danger_type=danger_type,
                        pattern=pattern.pattern,
                        preview=_preview(value),
                    )
        return None

    def iter_matches(
        self,
        value: str | None,
        danger_types: Iterable[DangerType] | None = None,
    ) -> Iterator[DangerMatch]:
        """Yield matches for value, limited to one per danger type."""
        if not value:
            return

        types_to_search = tuple(danger_types) if danger_types else tuple(DangerType)
        for danger_type in types_to_search:
            match = self.first_match(value, [danger_type])
            if match:
                yield match


def _preview(value: str, limit: int = 50) -> str:
    """Return a short, human-friendly preview of the offending string."""
    value = value.strip()
    if len(value) <= limit:
        return value
    return f"{value[:limit]}..."
