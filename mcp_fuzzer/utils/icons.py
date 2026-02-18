"""Lightweight icon/text helpers used across CLI and reporters.

Defaults stay plain ASCII to match existing tests and avoid rendering drift,
but you can switch themes by setting `MCP_FUZZER_ICON_THEME` to one of:
  - `ascii`   (default, backwards compatible)
  - `unicode` (✓ ✗ ⚠ 🛡 ⛔ 🔓 🎯 🚀 📊)
  - `emoji`   (✅ ❌ ⚠️ 🛡️ ⛔ 🔓 🎯 🚀 📈)
The theme is applied at import time, so set the env var before running the CLI.
"""

import os
from typing import Dict, Tuple


_THEMES: Dict[str, Dict[str, str]] = {
    "ascii": {
        "CHECK": "OK",
        "CROSS": "X",
        "ALERT": "ALERT",
        "SHIELD": "SHIELD",
        "BLOCKED": "BLOCKED",
        "UNLOCKED": "UNLOCKED",
        "TARGET": "TARGET",
        "ROCKET": "ROCKET",
        "STATS": "STATS",
    },
    "unicode": {
        "CHECK": "\u2713",
        "CROSS": "\u2717",
        "ALERT": "\u26a0",
        "SHIELD": "\U0001f6e1",
        "BLOCKED": "\u26d4",
        "UNLOCKED": "\U0001f513",
        "TARGET": "\U0001f3af",
        "ROCKET": "\U0001f680",
        "STATS": "\U0001f4ca",
    },
    "emoji": {
        "CHECK": "\u2705",
        "CROSS": "\u274c",
        "ALERT": "\u26a0\ufe0f",
        "SHIELD": "\U0001f6e1\ufe0f",
        "BLOCKED": "\u26d4",
        "UNLOCKED": "\U0001f513",
        "TARGET": "\U0001f3af",
        "ROCKET": "\U0001f680",
        "STATS": "\U0001f4c8",
    },
}


def _select_theme() -> Tuple[str, Dict[str, str]]:
    env_theme = os.getenv("MCP_FUZZER_ICON_THEME", "ascii").lower().strip()
    return (env_theme if env_theme in _THEMES else "ascii", _THEMES.get(env_theme, _THEMES["ascii"]))


_theme_name, _theme = _select_theme()

CHECK = _theme["CHECK"]
CROSS = _theme["CROSS"]
ALERT = _theme["ALERT"]
SHIELD = _theme["SHIELD"]
BLOCKED = _theme["BLOCKED"]
UNLOCKED = _theme["UNLOCKED"]
TARGET = _theme["TARGET"]
ROCKET = _theme["ROCKET"]
STATS = _theme["STATS"]


def current_theme() -> str:
    """Return the active icon theme name (ascii/unicode/emoji)."""
    return _theme_name


__all__ = [
    "CHECK",
    "CROSS",
    "ALERT",
    "SHIELD",
    "BLOCKED",
    "UNLOCKED",
    "TARGET",
    "ROCKET",
    "STATS",
    "current_theme",
]
