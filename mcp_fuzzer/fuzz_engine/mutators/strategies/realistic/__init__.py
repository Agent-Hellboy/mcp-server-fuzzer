"""
Realistic Strategy Module

This module contains strategies for generating realistic, valid data for fuzzing.
The realistic phase tests server behavior with expected, well-formed inputs.
"""

from .tool_strategy import (
    base64_strings,
    uuid_strings,
    timestamp_strings,
    generate_realistic_text,
    fuzz_tool_arguments_realistic,
)

from .protocol_type_strategy import (
    json_rpc_id_values,
    method_names,
    protocol_version_strings,
)

__all__ = [
    # Tool strategies
    "base64_strings",
    "uuid_strings",
    "timestamp_strings",
    "generate_realistic_text",
    "fuzz_tool_arguments_realistic",
    # Protocol strategies (Hypothesis helpers for tests)
    "json_rpc_id_values",
    "method_names",
    "protocol_version_strings",
]
