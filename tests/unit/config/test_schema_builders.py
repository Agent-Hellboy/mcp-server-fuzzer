#!/usr/bin/env python3
"""Unit tests for schema builder functions."""

from __future__ import annotations

import pytest

from mcp_fuzzer.config.schema.builders import (
    build_auth_schema,
    build_basic_schema,
    build_custom_transports_schema,
    build_fuzzing_schema,
    build_network_schema,
    build_output_schema,
    build_safety_schema,
    build_timeout_schema,
)
from mcp_fuzzer.config.schema.composer import get_config_schema


def test_build_timeout_schema():
    """Test that timeout schema includes all timeout-related fields."""
    schema = build_timeout_schema()
    assert "timeout" in schema
    assert "tool_timeout" in schema
    assert "http_timeout" in schema
    assert "sse_timeout" in schema
    assert "stdio_timeout" in schema
    assert all(field["type"] == "number" for field in schema.values())


def test_build_basic_schema():
    """Test that basic schema includes log level, safety, and fs_root."""
    schema = build_basic_schema()
    assert "log_level" in schema
    assert "safety_enabled" in schema
    assert "fs_root" in schema
    assert schema["log_level"]["type"] == "string"
    assert schema["safety_enabled"]["type"] == "boolean"


def test_build_fuzzing_schema():
    """Test that fuzzing schema includes mode, phase, protocol, etc."""
    schema = build_fuzzing_schema()
    assert "mode" in schema
    assert "phase" in schema
    assert "protocol" in schema
    assert "endpoint" in schema
    assert "runs" in schema
    assert "runs_per_type" in schema
    assert "max_concurrency" in schema


def test_build_network_schema():
    """Test that network schema includes network-related fields."""
    schema = build_network_schema()
    assert "no_network" in schema
    assert "allow_hosts" in schema
    assert schema["no_network"]["type"] == "boolean"
    assert schema["allow_hosts"]["type"] == "array"


def test_build_auth_schema():
    """Test that auth schema includes auth configuration."""
    schema = build_auth_schema()
    assert "auth" in schema
    auth_schema = schema["auth"]
    assert auth_schema["type"] == "object"
    assert "providers" in auth_schema["properties"]
    assert "mappings" in auth_schema["properties"]


def test_build_custom_transports_schema():
    """Test that custom transports schema is properly structured."""
    schema = build_custom_transports_schema()
    assert "custom_transports" in schema
    transport_schema = schema["custom_transports"]
    assert transport_schema["type"] == "object"
    assert "patternProperties" in transport_schema
    assert "additionalProperties" in transport_schema
    assert transport_schema["additionalProperties"] is False


def test_build_safety_schema():
    """Test that safety schema includes all safety-related fields."""
    schema = build_safety_schema()
    assert "safety" in schema
    safety_schema = schema["safety"]
    assert safety_schema["type"] == "object"
    props = safety_schema["properties"]
    assert "enabled" in props
    assert "local_hosts" in props
    assert "no_network" in props
    assert "header_denylist" in props


def test_build_output_schema():
    """Test that output schema includes output configuration."""
    schema = build_output_schema()
    assert "output" in schema
    output_schema = schema["output"]
    assert output_schema["type"] == "object"
    props = output_schema["properties"]
    assert "format" in props
    assert "directory" in props
    assert "compress" in props
    assert "types" in props
    assert "retention" in props


def test_get_config_schema_composition():
    """Test that get_config_schema composes all builder functions."""
    schema = get_config_schema()
    assert schema["type"] == "object"
    assert "properties" in schema

    properties = schema["properties"]
    # Check that all sections are included
    assert "timeout" in properties
    assert "log_level" in properties
    assert "mode" in properties
    assert "no_network" in properties
    assert "auth" in properties
    assert "custom_transports" in properties
    assert "safety" in properties
    assert "output" in properties


def test_get_config_schema_structure():
    """Test that the complete schema has proper JSON schema structure."""
    schema = get_config_schema()
    assert isinstance(schema, dict)
    assert "type" in schema
    assert "properties" in schema
    assert schema["type"] == "object"
    assert isinstance(schema["properties"], dict)


def test_schema_builders_are_independent():
    """Test that schema builders can be called independently."""
    timeout = build_timeout_schema()
    basic = build_basic_schema()
    fuzzing = build_fuzzing_schema()

    # Should not have overlapping keys
    assert not set(timeout.keys()) & set(basic.keys())
    assert not set(timeout.keys()) & set(fuzzing.keys())
    assert not set(basic.keys()) & set(fuzzing.keys())
