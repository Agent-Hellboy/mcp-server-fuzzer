#!/usr/bin/env python3
"""
Realistic Protocol Type Strategy

Hypothesis strategies for generating realistic protocol data (used in tests).
"""

from hypothesis import strategies as st


def protocol_version_strings() -> st.SearchStrategy[str]:
    """Generate realistic protocol version strings."""
    date_versions = st.builds(
        lambda year, month, day: f"{year:04d}-{month:02d}-{day:02d}",
        st.integers(min_value=2020, max_value=2030),
        st.integers(min_value=1, max_value=12),
        st.integers(min_value=1, max_value=28),
    )
    semantic_versions = st.builds(
        lambda major, minor, patch: f"{major}.{minor}.{patch}",
        st.integers(min_value=0, max_value=10),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=999),
    )
    return st.one_of(date_versions, semantic_versions)


def json_rpc_id_values() -> st.SearchStrategy:
    """Generate valid JSON-RPC ID values."""
    return st.one_of(st.none(), st.text(min_size=1, max_size=50), st.integers())


def method_names() -> st.SearchStrategy[str]:
    """Generate realistic method names for JSON-RPC calls."""
    prefixes = st.sampled_from([
        "initialize", "initialized", "ping", "pong",
        "tools/list", "tools/call", "resources/list", "resources/read",
        "prompts/list", "prompts/get", "logging/setLevel",
        "notifications/", "completion/", "sampling/",
    ])
    simple_names = st.text(
        alphabet=st.characters(
            whitelist_categories=("Lu", "Ll", "Nd"),
            whitelist_characters="_-./:",
        ),
        min_size=3,
        max_size=30,
    ).filter(lambda x: x and x[0].isalpha())
    return st.one_of(prefixes, simple_names)
