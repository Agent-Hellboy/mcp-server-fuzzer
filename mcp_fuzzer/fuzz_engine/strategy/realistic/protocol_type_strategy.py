#!/usr/bin/env python3
"""
Realistic Protocol Type Strategy

This module provides strategies for generating realistic protocol messages and types.
Used in the realistic phase to test server behavior with valid MCP protocol data.
"""

import random
from typing import Any, Dict

from hypothesis import strategies as st


def protocol_version_strings() -> st.SearchStrategy[str]:
    """
    Generate realistic protocol version strings.

    Returns:
        Strategy that generates version strings like "2024-11-05", "1.0.0", etc.
    """
    # Date-based versions (like MCP uses)
    date_versions = st.builds(
        lambda year, month, day: f"{year:04d}-{month:02d}-{day:02d}",
        st.integers(min_value=2020, max_value=2030),
        st.integers(min_value=1, max_value=12),
        st.integers(min_value=1, max_value=28),  # Safe day range
    )

    # Semantic versions
    semantic_versions = st.builds(
        lambda major, minor, patch: f"{major}.{minor}.{patch}",
        st.integers(min_value=0, max_value=10),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=999),
    )

    return st.one_of(date_versions, semantic_versions)


def json_rpc_id_values() -> st.SearchStrategy:
    """
    Generate valid JSON-RPC ID values.

    JSON-RPC IDs can be strings, numbers, or null.

    Returns:
        Strategy that generates valid JSON-RPC ID values
    """
    return st.one_of(
        st.none(),
        st.text(min_size=1, max_size=50),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
    )


def method_names() -> st.SearchStrategy[str]:
    """
    Generate realistic method names for JSON-RPC calls.

    Returns:
        Strategy that generates method name strings
    """
    # Common prefixes for MCP and similar protocols
    prefixes = st.sampled_from(
        [
            "initialize",
            "initialized",
            "ping",
            "pong",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "logging/setLevel",
            "notifications/",
            "completion/",
            "sampling/",
        ]
    )

    # Simple method names
    simple_names = st.text(
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters="_-./:"
        ),
        min_size=3,
        max_size=30,
    ).filter(lambda x: x and x[0].isalpha())

    return st.one_of(prefixes, simple_names)


# TODO: expand this to cover all the InitializeRequest fields
def fuzz_initialize_request_realistic() -> Dict[str, Any]:
    """Generate realistic InitializeRequest for testing valid behavior."""
    # Use realistic protocol versions
    protocol_versions = [
        protocol_version_strings().example(),
        protocol_version_strings().example(),
        "2024-11-05",  # Latest MCP version
        "2024-10-01",  # Another valid date format
        "1.0.0",  # Semantic version
    ]

    # Use realistic JSON-RPC IDs
    id_options = [
        json_rpc_id_values().example(),
        json_rpc_id_values().example(),
        json_rpc_id_values().example(),
        1,
        2,
        3,  # Simple integers
        "req-001",
        "req-002",  # String IDs
    ]

    # Use realistic method names
    method_options = [
        "initialize",  # Correct method
        method_names().example(),
        method_names().example(),
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.choice(id_options),
        "method": random.choice(method_options),
        "params": {
            "protocolVersion": random.choice(protocol_versions),
            # Align with MCP ClientCapabilities spec: include valid fields only
            # https://modelcontextprotocol.io/specification/draft/schema#ClientCapabilities
            "capabilities": {
                "elicitation": {},
                "experimental": {},
                "roots": {"listChanged": True},
                "sampling": {},
            },
            "clientInfo": {"name": "test-client", "version": "1.0.0"},
        },
    }
