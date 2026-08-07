"""Lightweight icon/text helpers used across CLI and reporters.

Defaults stay plain ASCII so output reads like other security tooling
(nmap/semgrep/trivy) and stays greppable, but you can switch themes by setting
`MCP_FUZZER_ICON_THEME` to one of:
  - `ascii`   (default, backwards compatible)
  - `unicode` (checkmark/ballot-x/warning plus a few pictographs)
  - `emoji`   (full pictographs)

The theme is resolved at import time from the environment, so set the env var
before running the CLI. It can also be switched at runtime with
:func:`set_theme` (e.g. from a CLI flag). Note that modules which did
``from .icons import CHECK`` bind the glyph at *their* import time; call
:func:`icon` / :func:`severity_icon` if a call site must follow later
:func:`set_theme` changes.

Severity markers (``CRITICAL``/``HIGH``/``MEDIUM``/``LOW``/``INFO``) are themed
the same way and are keyed by the same lowercase severity strings that
``mcp_fuzzer.diagnostics.model.Finding.severity`` uses; lookups are
case-insensitive and unknown severities fall back to ``INFO``.
"""

from __future__ import annotations

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

DEFAULT_THEME = "ascii"

# Severity levels, ordered most to least severe.
SEVERITY_LEVELS: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_SEVERITY_THEMES: Dict[str, Dict[str, str]] = {
    "ascii": {
        "CRITICAL": "CRIT",
        "HIGH": "HIGH",
        "MEDIUM": "MED",
        "LOW": "LOW",
        "INFO": "INFO",
    },
    "unicode": {
        "CRITICAL": "\u25cf",
        "HIGH": "\u25c6",
        "MEDIUM": "\u25b2",
        "LOW": "\u25aa",
        "INFO": "\u2022",
    },
    "emoji": {
        "CRITICAL": "\U0001f534",
        "HIGH": "\U0001f7e0",
        "MEDIUM": "\U0001f7e1",
        "LOW": "\U0001f535",
        "INFO": "\u2139\ufe0f",
    },
}

# Rich colour names paired with each severity. Themed like the glyphs so a
# future theme can override them; today every theme shares one palette.
_BASE_SEVERITY_COLORS: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "blue",
}
_SEVERITY_COLOR_THEMES: Dict[str, Dict[str, str]] = {
    theme: dict(_BASE_SEVERITY_COLORS) for theme in _THEMES
}


def _normalize_theme(name: str | None) -> str:
    """Return a known theme name, falling back to ascii for anything else."""
    key = str(name or "").lower().strip()
    return key if key in _THEMES else DEFAULT_THEME


def _select_theme() -> Tuple[str, Dict[str, str]]:
    env_theme = os.getenv("MCP_FUZZER_ICON_THEME", DEFAULT_THEME).lower().strip()
    name = env_theme if env_theme in _THEMES else DEFAULT_THEME
    return name, _THEMES.get(env_theme, _THEMES[DEFAULT_THEME])


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

SEVERITY_ICONS: Dict[str, str] = dict(_SEVERITY_THEMES[_theme_name])
SEVERITY_COLORS: Dict[str, str] = dict(_SEVERITY_COLOR_THEMES[_theme_name])

SEVERITY_CRITICAL = SEVERITY_ICONS["CRITICAL"]
SEVERITY_HIGH = SEVERITY_ICONS["HIGH"]
SEVERITY_MEDIUM = SEVERITY_ICONS["MEDIUM"]
SEVERITY_LOW = SEVERITY_ICONS["LOW"]
SEVERITY_INFO = SEVERITY_ICONS["INFO"]


def _active(mapping: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Return `mapping`'s entry for the active theme (ascii if unknown)."""
    return mapping.get(_theme_name, mapping[DEFAULT_THEME])


def current_theme() -> str:
    """Return the active icon theme name (ascii/unicode/emoji)."""
    return _theme_name


def available_themes() -> Tuple[str, ...]:
    """Return the selectable theme names, ascii first."""
    return tuple(_THEMES)


def set_theme(name: str | None = None) -> str:
    """Switch the active theme and rebind the module-level constants.

    Passing ``None`` re-resolves the theme from ``MCP_FUZZER_ICON_THEME``.
    Unknown names fall back to ``ascii``. Returns the applied theme name.
    """
    resolved = _select_theme()[0] if name is None else _normalize_theme(name)
    glyphs = _THEMES[resolved]
    severity = _SEVERITY_THEMES[resolved]

    module = globals()
    module["_theme_name"] = resolved
    module["_theme"] = glyphs
    # Theme keys are the constant names (CHECK, CROSS, ...).
    module.update(glyphs)
    module.update({f"SEVERITY_{key}": value for key, value in severity.items()})
    module["SEVERITY_ICONS"] = dict(severity)
    module["SEVERITY_COLORS"] = dict(_SEVERITY_COLOR_THEMES[resolved])
    return resolved


def icon(name: str) -> str:
    """Return the glyph for `name` under the active theme, or "" if unknown."""
    return _active(_THEMES).get(str(name).upper().strip(), "")


def severity_icon(severity: str) -> str:
    """Return the marker for `severity` (case-insensitive, unknown -> INFO)."""
    icons = _active(_SEVERITY_THEMES)
    return icons.get(str(severity).upper().strip(), icons["INFO"])


def severity_color(severity: str) -> str:
    """Return the rich colour for `severity` (case-insensitive, unknown -> INFO)."""
    colors = _active(_SEVERITY_COLOR_THEMES)
    return colors.get(str(severity).upper().strip(), colors["INFO"])


def severity_label(severity: str) -> str:
    """Return "<marker> <SEVERITY>" for `severity`, ready to print."""
    return f"{severity_icon(severity)} {str(severity).upper().strip()}".strip()


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
    "DEFAULT_THEME",
    "SEVERITY_LEVELS",
    "SEVERITY_ICONS",
    "SEVERITY_COLORS",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "SEVERITY_MEDIUM",
    "SEVERITY_LOW",
    "SEVERITY_INFO",
    "available_themes",
    "current_theme",
    "icon",
    "set_theme",
    "severity_color",
    "severity_icon",
    "severity_label",
]
