"""Tests for shared CLI/report icon helpers."""

from __future__ import annotations

import pytest

import mcp_fuzzer.icons as icons


@pytest.fixture(autouse=True)
def _restore_theme():
    """Keep module-level icon state stable across tests."""
    original = icons.current_theme()
    yield
    icons.set_theme(original)


def test_current_theme_returns_configured_name(monkeypatch):
    monkeypatch.setattr(icons, "_theme_name", "ascii")
    assert icons.current_theme() == "ascii"


def test_ascii_theme_is_the_default_and_plain():
    icons.set_theme("ascii")
    assert icons.current_theme() == "ascii"
    assert (icons.CHECK, icons.CROSS, icons.ALERT) == ("OK", "X", "ALERT")
    assert icons.SEVERITY_CRITICAL == "CRIT"
    assert all(glyph.isascii() for glyph in icons.SEVERITY_ICONS.values())


@pytest.mark.parametrize("theme", ["ascii", "unicode", "emoji"])
def test_select_theme_honours_env(monkeypatch, theme):
    monkeypatch.setenv("MCP_FUZZER_ICON_THEME", theme)
    name, glyphs = icons._select_theme()
    assert name == theme
    assert glyphs is icons._THEMES[theme]


@pytest.mark.parametrize("value", ["", "  ", "nope", "ASCII-ART"])
def test_select_theme_falls_back_to_ascii(monkeypatch, value):
    monkeypatch.setenv("MCP_FUZZER_ICON_THEME", value)
    name, glyphs = icons._select_theme()
    assert name == "ascii"
    assert glyphs is icons._THEMES["ascii"]


def test_select_theme_is_case_and_space_insensitive(monkeypatch):
    monkeypatch.setenv("MCP_FUZZER_ICON_THEME", "  EMOJI ")
    assert icons._select_theme()[0] == "emoji"


def test_available_themes_lists_ascii_first():
    assert icons.available_themes()[0] == "ascii"
    assert set(icons.available_themes()) == {"ascii", "unicode", "emoji"}


def test_set_theme_rebinds_module_constants():
    assert icons.set_theme("emoji") == "emoji"
    assert icons.current_theme() == "emoji"
    assert icons.CHECK == icons._THEMES["emoji"]["CHECK"]
    assert icons.SHIELD == icons._THEMES["emoji"]["SHIELD"]
    assert icons.SEVERITY_CRITICAL == icons._SEVERITY_THEMES["emoji"]["CRITICAL"]
    assert icons.SEVERITY_ICONS == icons._SEVERITY_THEMES["emoji"]

    assert icons.set_theme("ascii") == "ascii"
    assert icons.CHECK == "OK"
    assert icons.SEVERITY_CRITICAL == "CRIT"


def test_set_theme_unknown_name_falls_back_to_ascii():
    icons.set_theme("emoji")
    assert icons.set_theme("klingon") == "ascii"
    assert icons.current_theme() == "ascii"
    assert icons.CHECK == "OK"


def test_set_theme_without_name_rereads_env(monkeypatch):
    icons.set_theme("emoji")
    monkeypatch.setenv("MCP_FUZZER_ICON_THEME", "unicode")
    assert icons.set_theme() == "unicode"
    assert icons.CHECK == icons._THEMES["unicode"]["CHECK"]

    monkeypatch.delenv("MCP_FUZZER_ICON_THEME", raising=False)
    assert icons.set_theme() == "ascii"


def test_set_theme_exposes_copies_not_theme_tables():
    icons.set_theme("ascii")
    icons.SEVERITY_ICONS["CRITICAL"] = "tampered"
    icons.SEVERITY_COLORS["CRITICAL"] = "tampered"
    icons.set_theme("ascii")
    assert icons._SEVERITY_THEMES["ascii"]["CRITICAL"] == "CRIT"
    assert icons.SEVERITY_ICONS["CRITICAL"] == "CRIT"
    assert icons.SEVERITY_COLORS["CRITICAL"] == "bold red"


def test_icon_lookup_follows_active_theme():
    icons.set_theme("unicode")
    assert icons.icon("CHECK") == icons._THEMES["unicode"]["CHECK"]
    assert icons.icon("check") == icons.icon("  Check ")
    assert icons.icon("no-such-icon") == ""


@pytest.mark.parametrize("theme", ["ascii", "unicode", "emoji"])
def test_every_theme_defines_every_severity(theme):
    assert set(icons._SEVERITY_THEMES[theme]) == set(icons.SEVERITY_LEVELS)
    assert set(icons._SEVERITY_COLOR_THEMES[theme]) == set(icons.SEVERITY_LEVELS)
    assert set(icons._THEMES[theme]) == set(icons._THEMES["ascii"])


def test_severity_levels_are_ordered_most_to_least_severe():
    assert icons.SEVERITY_LEVELS == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@pytest.mark.parametrize(
    "severity", ["critical", "HIGH", " medium ", "Low", "info"]
)
def test_severity_icon_is_case_insensitive(severity):
    icons.set_theme("ascii")
    key = severity.strip().upper()
    assert icons.severity_icon(severity) == icons._SEVERITY_THEMES["ascii"][key]
    assert icons.severity_color(severity) == icons._BASE_SEVERITY_COLORS[key]


@pytest.mark.parametrize("severity", ["", "unknown", None, "warning"])
def test_unknown_severity_degrades_to_info(severity):
    icons.set_theme("ascii")
    assert icons.severity_icon(severity) == icons.SEVERITY_INFO
    assert icons.severity_color(severity) == icons.SEVERITY_COLORS["INFO"]


def test_severity_helpers_follow_theme_changes():
    icons.set_theme("emoji")
    assert icons.severity_icon("critical") == icons._SEVERITY_THEMES["emoji"][
        "CRITICAL"
    ]
    icons.set_theme("ascii")
    assert icons.severity_icon("critical") == "CRIT"


def test_severity_helpers_survive_unknown_active_theme(monkeypatch):
    monkeypatch.setattr(icons, "_theme_name", "not-a-theme")
    assert icons.severity_icon("critical") == "CRIT"
    assert icons.severity_color("critical") == "bold red"
    assert icons.icon("CHECK") == "OK"


def test_severity_label_is_printable():
    icons.set_theme("ascii")
    assert icons.severity_label("critical") == "CRIT CRITICAL"
    assert icons.severity_label("info") == "INFO INFO"


def test_severity_vocabulary_matches_finding_severities():
    from mcp_fuzzer.diagnostics.model import SEVERITY_ORDER

    assert {level.lower() for level in icons.SEVERITY_LEVELS} == set(SEVERITY_ORDER)


def test_public_api_is_exported():
    for name in icons.__all__:
        assert hasattr(icons, name), name
