#!/usr/bin/env python3
"""
Unit tests for the path_sanitizer helpers.
"""

from __future__ import annotations

from pathlib import Path

from mcp_fuzzer.safety_system.filesystem import PathSanitizer


class DummySandbox:
    """Minimal sandbox stub used to validate sanitization heuristics."""

    def __init__(self, root: Path):
        self.root = root

    def is_path_safe(self, value: str) -> bool:
        return value.startswith(str(self.root))

    def sanitize_path(self, value: str) -> str:
        return str(self.root / Path(value).name)


def test_sanitizer_rewrites_path_like_values(tmp_path):
    sandbox = DummySandbox(tmp_path)
    sanitizer = PathSanitizer(sandbox)

    arguments = {
        "path": "/etc/passwd",
        "filename": "notes.txt",
        "content": "not a path",
        "nested": {
            "output_dir": "/var/tmp",
        },
        "files": ["/usr/bin/python", "README.md"],
    }

    sanitized = sanitizer.sanitize_arguments(arguments, "test_tool")

    assert sanitized["path"].startswith(str(tmp_path))
    assert sanitized["filename"].startswith(str(tmp_path))
    assert sanitized["content"] == "not a path"
    assert sanitized["nested"]["output_dir"].startswith(str(tmp_path))
    assert all(item.startswith(str(tmp_path)) for item in sanitized["files"])
