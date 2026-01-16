#!/usr/bin/env python3
"""
Filesystem path sanitization helpers.

SafetyFilter previously embedded a large recursive function that attempted to
detect path-like values and rewrite them inside the sandbox.  Extracting the
logic into this module keeps safety.py focused on policy decisions while this
module owns the heuristics for identifying and rewriting filesystem arguments.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any


FILESYSTEM_ARG_NAMES = {
    "path",
    "file",
    "filename",
    "filepath",
    "directory",
    "dir",
    "folder",
    "source",
    "destination",
    "dest",
    "target",
    "output",
    "input",
    "root",
    "base",
    "location",
    "where",
    "to",
    "from",
}

_COMMON_FILE_SUFFIXES = (
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".log",
    ".md",
    ".py",
    ".js",
    ".html",
    ".css",
    ".xml",
    ".csv",
)


class PathSanitizer:
    """Apply sandbox-aware path sanitization to arbitrary argument trees."""

    def __init__(self, sandbox: Any):
        self._sandbox = sandbox

    def sanitize_arguments(
        self,
        arguments: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any]:
        return self._sanitize_mapping(arguments, tool_name)

    # ------------------------------------------------------------------ helpers
    def _sanitize_mapping(
        self,
        data: dict[str, Any],
        tool_name: str,
    ) -> dict[str, Any]:
        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            sanitized[key] = self._sanitize_value(key, value, tool_name)
        return sanitized

    def _sanitize_sequence(
        self,
        items: list[Any],
        key: str,
        tool_name: str,
    ) -> list[Any]:
        sanitized_list: list[Any] = []
        for idx, item in enumerate(items):
            sanitized_list.append(
                self._sanitize_value(f"{key}[{idx}]", item, tool_name)
            )
        return sanitized_list

    def _sanitize_value(self, key: str, value: Any, tool_name: str) -> Any:
        if isinstance(value, dict):
            return self._sanitize_mapping(value, tool_name)
        if isinstance(value, list):
            return self._sanitize_sequence(value, key, tool_name)
        if isinstance(value, (str, Path)):
            return self._sanitize_string_value(key, str(value), tool_name)
        return value

    def _sanitize_string_value(self, key: str, value: str, tool_name: str) -> str:
        if not value or not self._looks_like_path(key, value):
            return value

        if self._sandbox.is_path_safe(value):
            return value

        sanitized = self._sandbox.sanitize_path(value)
        logging.info(
            "Sanitized filesystem path '%s': '%s' -> '%s'",
            key,
            value,
            sanitized,
        )
        return sanitized

    @staticmethod
    def _looks_like_path(key: str, value: str) -> bool:
        if not value:
            return False

        # Exclude script/HTML/URL content - these are fuzzing inputs, not paths
        # Check this FIRST before any path detection logic
        value_lower = value.lower().strip()
        if value_lower.startswith(("<script", "<html", "<body", "<div", "<span")):
            return False
        if value_lower.startswith(("http://", "https://", "file://", "ftp://")):
            return False
        if "://" in value_lower:
            return False
        # Exclude HTML/script-like content (contains tags)
        if "<" in value_lower and ">" in value_lower:
            return False

        normalized_key = key.lower()
        if normalized_key in FILESYSTEM_ARG_NAMES:
            return True

        # Only treat as path if it contains path separators
        if "/" in value or "\\" in value:
            return True

        if value_lower.endswith(_COMMON_FILE_SUFFIXES):
            return True

        return False
