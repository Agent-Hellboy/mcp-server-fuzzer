"""
Aggressive Strategy Module

This module contains strategies for generating malicious, malformed, and edge-case
data for fuzzing. The aggressive phase tests server security and robustness with
attack vectors and invalid inputs.
"""

from .tool_strategy import (
    generate_aggressive_text,
    fuzz_tool_arguments_aggressive,
)

__all__ = [
    # Tool strategies
    "generate_aggressive_text",
    "fuzz_tool_arguments_aggressive",
]
