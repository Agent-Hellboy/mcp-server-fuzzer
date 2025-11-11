#!/usr/bin/env python3
"""
Unit tests for the detectors module.
"""

from __future__ import annotations

import pytest

from mcp_fuzzer.safety_system.detection import DangerDetector, DangerType


@pytest.fixture()
def detector() -> DangerDetector:
    return DangerDetector(
        url_patterns=[r"https?://", r"ftp://"],
        script_patterns=[r"<script", r"javascript:"],
        command_patterns=[r"rm\s+-rf", r"shutdown"],
    )


def test_contains_matches_expected_types(detector: DangerDetector):
    assert detector.contains("https://example.com", DangerType.URL)
    assert detector.contains("<script>alert(1)</script>", DangerType.SCRIPT)
    assert detector.contains("rm -rf /", DangerType.COMMAND)
    assert not detector.contains("plain text", DangerType.URL)


def test_first_match_returns_preview(detector: DangerDetector):
    match = detector.first_match(
        "Visit https://example.com and run rm -rf /", [DangerType.URL]
    )
    assert match is not None
    assert match.danger_type is DangerType.URL
    assert "https://example.com" in match.preview


def test_iter_matches_limits_to_one_per_type(detector: DangerDetector):
    value = "rm -rf / && shutdown now"
    matches = list(detector.iter_matches(value))
    command_matches = [m for m in matches if m.danger_type is DangerType.COMMAND]
    assert len(command_matches) == 1
