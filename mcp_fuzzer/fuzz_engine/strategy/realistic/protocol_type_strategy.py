#!/usr/bin/env python3
"""
Realistic Protocol Type Strategy

This module provides strategies for generating realistic protocol messages and types.
Used in the realistic phase to test server behavior with valid MCP protocol data.
"""

import random
from typing import Any, Dict

from hypothesis import strategies as st
from ....config import DEFAULT_PROTOCOL_VERSION


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
            whitelist_categories=("Lu", "Ll", "Nd"),
            whitelist_characters="_-./:",
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
        DEFAULT_PROTOCOL_VERSION,  # Current MCP version
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

    return {
        "jsonrpc": "2.0",
        "id": random.choice(id_options),
        "method": "initialize",
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


def fuzz_list_resources_request_realistic() -> Dict[str, Any]:
    """Generate realistic ListResourcesRequest for testing valid behavior."""
    cursor_options = [
        None,  # No cursor
        "cursor-123",
        "next-page-token",
        "eyJwYWdlIjoxfQ==",  # base64 encoded page info
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "resources/list",
        "params": {
            "cursor": random.choice(cursor_options) if random.random() < 0.3 else None,
        },
    }


def fuzz_read_resource_request_realistic() -> Dict[str, Any]:
    """Generate realistic ReadResourceRequest for testing valid behavior."""
    uri_options = [
        "file:///home/user/documents/readme.txt",
        "file:///etc/hosts",
        "file:///var/log/application.log",
        "file:///tmp/session-data.json",
        "http://localhost:8080/api/data",
        "https://api.example.com/v1/users",
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "resources/read",
        "params": {
            "uri": random.choice(uri_options),
        },
    }


def fuzz_subscribe_request_realistic() -> Dict[str, Any]:
    """Generate realistic SubscribeRequest for testing valid behavior."""
    uri_options = [
        "file:///home/user/documents/",
        "file:///var/log/",
        "file:///tmp/notifications/",
        "http://localhost:8080/api/events",
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "resources/subscribe",
        "params": {
            "uri": random.choice(uri_options),
        },
    }


def fuzz_unsubscribe_request_realistic() -> Dict[str, Any]:
    """Generate realistic UnsubscribeRequest for testing valid behavior."""
    uri_options = [
        "file:///home/user/documents/",
        "file:///var/log/",
        "file:///tmp/notifications/",
        "http://localhost:8080/api/events",
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "resources/unsubscribe",
        "params": {
            "uri": random.choice(uri_options),
        },
    }


def fuzz_list_prompts_request_realistic() -> Dict[str, Any]:
    """Generate realistic ListPromptsRequest for testing valid behavior."""
    cursor_options = [
        None,
        "prompt-cursor-456",
        "next-prompts-page",
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "prompts/list",
        "params": {
            "cursor": random.choice(cursor_options) if random.random() < 0.3 else None,
        },
    }


def fuzz_get_prompt_request_realistic() -> Dict[str, Any]:
    """Generate realistic GetPromptRequest for testing valid behavior."""
    name_options = [
        "code-review",
        "documentation",
        "debug-help",
        "api-design",
        "security-audit",
    ]

    argument_options = [
        None,
        {"language": "python", "framework": "flask"},
        {"type": "bug-fix", "severity": "high"},
        {"format": "markdown", "length": "detailed"},
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "prompts/get",
        "params": {
            "name": random.choice(name_options),
            "arguments": random.choice(argument_options),
        },
    }


def fuzz_list_roots_request_realistic() -> Dict[str, Any]:
    """Generate realistic ListRootsRequest for testing valid behavior."""
    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "roots/list",
        "params": {},
    }


def fuzz_set_level_request_realistic() -> Dict[str, Any]:
    """Generate realistic SetLevelRequest for testing valid behavior."""
    level_options = ["debug", "info", "warning", "error", "critical"]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "logging/setLevel",
        "params": {
            "level": random.choice(level_options),
        },
    }


def fuzz_complete_request_realistic() -> Dict[str, Any]:
    """Generate realistic CompleteRequest for testing valid behavior."""
    ref_options = [
        {"type": "ref/prompt", "name": "code-review"},
        {"type": "ref/resource", "uri": "file:///home/user/docs/"},
        {"type": "ref/function", "name": "analyze_code"},
    ]

    argument_options = [
        {"prefix": "import ", "suffix": ""},
        {"prefix": "def ", "suffix": "(", "cursor": 4},
        {"prefix": "class ", "suffix": ":", "cursor": 6},
        {"prefix": "SELECT ", "suffix": " FROM", "cursor": 7},
    ]

    return {
        "jsonrpc": "2.0",
        "id": random.randint(1, 1000),
        "method": "completion/complete",
        "params": {
            "ref": random.choice(ref_options),
            "argument": random.choice(argument_options),
        },
    }
