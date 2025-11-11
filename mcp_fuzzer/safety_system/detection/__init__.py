#!/usr/bin/env python3
"""Detection utilities for the safety system."""

from .detector import DangerDetector, DangerMatch, DangerType
from .patterns import (
    DEFAULT_DANGEROUS_URL_PATTERNS,
    DEFAULT_DANGEROUS_SCRIPT_PATTERNS,
    DEFAULT_DANGEROUS_COMMAND_PATTERNS,
    DEFAULT_DANGEROUS_ARGUMENT_NAMES,
)

__all__ = [
    "DangerDetector",
    "DangerMatch",
    "DangerType",
    "DEFAULT_DANGEROUS_URL_PATTERNS",
    "DEFAULT_DANGEROUS_SCRIPT_PATTERNS",
    "DEFAULT_DANGEROUS_COMMAND_PATTERNS",
    "DEFAULT_DANGEROUS_ARGUMENT_NAMES",
]
