"""Process exit codes for the CLI fuzzer."""

from __future__ import annotations

SUCCESS = 0
"""Normal completion."""

GENERAL_ERROR = 1
"""Validation, bootstrap, or execution failure."""

NO_TOOLS_AVAILABLE = 2
"""No tools discovered and ``--fail-if-no-tools`` is set."""

INTERRUPTED = 130
"""Run stopped by user interrupt (SIGINT / Ctrl+C)."""

__all__ = [
    "GENERAL_ERROR",
    "INTERRUPTED",
    "NO_TOOLS_AVAILABLE",
    "SUCCESS",
]
