#!/usr/bin/env python3
"""
Structured logging helpers for blocked safety events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from ..detection import DangerDetector, DangerMatch, DangerType


@dataclass
class DangerousArgument:
    """A summarized view of dangerous content detected in tool arguments."""

    key: str
    match: DangerMatch


@dataclass
class BlockedOperation:
    """Structured representation of a blocked tool invocation."""

    timestamp: str
    tool_name: str
    reason: str
    arguments: dict[str, Any]
    dangerous_content: list[DangerousArgument]


class SafetyEventLogger:
    """
    Builds structured summaries for blocked operations so that the SafetyFilter
    can keep its public API lean while we reuse the same formatting in logs and
    telemetry.
    """

    def __init__(self, detector: DangerDetector):
        self._detector = detector

    def build_blocked_operation(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        reason: str,
    ) -> BlockedOperation:
        timestamp = datetime.now().isoformat()
        safe_arguments, dangerous_content = self._summarize_arguments(arguments or {})
        return BlockedOperation(
            timestamp=timestamp,
            tool_name=tool_name,
            reason=reason,
            arguments=safe_arguments,
            dangerous_content=dangerous_content,
        )

    # ------------------------------------------------------------------ helpers
    def _summarize_arguments(
        self,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], list[DangerousArgument]]:
        safe_arguments: dict[str, Any] = {}
        dangerous_content: list[DangerousArgument] = []

        for key, value in arguments.items():
            summary, detected = self._summarize_value(key, value)
            safe_arguments[key] = summary
            dangerous_content.extend(detected)

        return safe_arguments, dangerous_content

    def _summarize_value(
        self,
        key: str,
        value: Any,
    ) -> tuple[Any, list[DangerousArgument]]:
        if isinstance(value, str):
            return _truncate(value), list(self._dangerous_matches(key, value))
        if isinstance(value, list):
            return self._summarize_list(key, value)
        if isinstance(value, dict):
            nested_safe, nested_danger = self._summarize_arguments(value)
            return nested_safe, nested_danger
        return value, []

    def _summarize_list(
        self,
        key: str,
        items: Iterable[Any],
    ) -> tuple[Any, list[DangerousArgument]]:
        items = list(items)
        preview = items
        if len(items) > 10:
            preview = f"[{len(items)} items] - {items[:3]}..."

        dangerous: list[DangerousArgument] = []
        for idx, item in enumerate(items[:5]):
            if isinstance(item, str):
                dangerous.extend(self._dangerous_matches(f"{key}[{idx}]", item))
            elif isinstance(item, dict):
                _, nested_danger = self._summarize_arguments(item)
                dangerous.extend(nested_danger)
        return preview, dangerous

    def _dangerous_matches(
        self,
        key: str,
        value: str,
    ) -> Iterable[DangerousArgument]:
        for match in self._detector.iter_matches(
            value, [DangerType.URL, DangerType.COMMAND]
        ):
            yield DangerousArgument(key=key, match=match)


def _truncate(value: str, limit: int = 100) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}..."
