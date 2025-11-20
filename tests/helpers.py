"""Testing helpers used across multiple suites."""

from __future__ import annotations

from typing import Any


MISSING = object()


def get_nested(data: dict[str, Any], *keys: str, default: Any = MISSING) -> Any:
    """Safely traverse nested dictionaries without exposing internal structure."""
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current
