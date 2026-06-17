"""Tests for shared CLI/report icon helpers."""

from __future__ import annotations

import mcp_fuzzer.icons as icons


def test_current_theme_returns_configured_name(monkeypatch):
    monkeypatch.setattr(icons, "_theme_name", "ascii")
    assert icons.current_theme() == "ascii"
