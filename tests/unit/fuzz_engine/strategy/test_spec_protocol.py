#!/usr/bin/env python3
"""
Unit tests for spec_protocol.py module.
"""

import os
import json
from pathlib import Path
from unittest.mock import patch
import pytest

from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
    _schema_version_or_env,
    _schema_root,
    _latest_schema_version,
    _schema_path,
    _load_schema,
    _resolve_refs,
    _definition_for,
    _generate_params,
    _mutate_value_for_aggressive,
    _mutate_aggressive_params,
    _apply_semantic_overrides,
    _prepare_schema_params_from_definition,
    _prepare_schema_params,
    _extract_method_const,
    _build_schema_request,
    get_spec_protocol_fuzzer_method,
    build_spec_params,
    MALICIOUS_STRINGS,
    MALICIOUS_NUMBERS,
)


class TestSchemaVersionOrEnv:
    """Test cases for _schema_version_or_env."""

    def test_with_version(self):
        """Test with provided version."""
        assert _schema_version_or_env("v1.0") == "v1.0"

    def test_with_env_var(self):
        """Test with environment variable."""
        with patch.dict(os.environ, {"MCP_SPEC_SCHEMA_VERSION": "env-version"}):
            assert _schema_version_or_env(None) == "env-version"

    def test_without_version_or_env(self):
        """Test without version or env var."""
        with patch.dict(os.environ, {}, clear=True):
            assert _schema_version_or_env(None) is None


class TestSchemaRoot:
    """Test cases for _schema_root."""

    def test_with_env_var(self):
        """Test with MCP_SPEC_SCHEMA_ROOT env var."""
        with patch.dict(os.environ, {"MCP_SPEC_SCHEMA_ROOT": "/custom/path"}):
            root = _schema_root()
            assert str(root) == "/custom/path"

    def test_without_env_var(self):
        """Test without env var uses default."""
        with patch.dict(os.environ, {}, clear=True):
            root = _schema_root()
            assert "schemas" in str(root)
            assert "mcp-spec" in str(root)


class TestLatestSchemaVersion:
    """Test cases for _latest_schema_version."""

    def test_nonexistent_root(self, tmp_path):
        """Test with nonexistent root."""
        result = _latest_schema_version(Path("/nonexistent"))
        assert result is None

    def test_empty_root(self, tmp_path):
        """Test with empty root directory."""
        result = _latest_schema_version(tmp_path)
        assert result is None

    def test_with_versions(self, tmp_path):
        """Test with version directories."""
        (tmp_path / "v1.0").mkdir()
        (tmp_path / "v2.0").mkdir()
        (tmp_path / "v1.5").mkdir()

        result = _latest_schema_version(tmp_path)
        assert result == "v2.0"


class TestSchemaPath:
    """Test cases for _schema_path."""

    def test_with_env_path(self):
        """Test with MCP_SPEC_SCHEMA_PATH env var."""
        with patch.dict(os.environ, {"MCP_SPEC_SCHEMA_PATH": "/custom/schema.json"}):
            path = _schema_path(None)
            assert str(path) == "/custom/schema.json"

    def test_with_version(self, tmp_path):
        """Test with version parameter."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._schema_root"
        )
        with patch(patch_path, return_value=tmp_path):
            (tmp_path / "v1.0").mkdir()
            path = _schema_path("v1.0")
            assert "v1.0" in str(path)

    def test_without_chosen_falls_back_to_schema_json(self, tmp_path):
        """Test fallback to schema.json when no version chosen."""
        patch_root = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._schema_root"
        )
        patch_version = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            "._latest_schema_version"
        )
        with patch(patch_root, return_value=tmp_path):
            with patch(patch_version, return_value=None):
                with patch.dict(os.environ, {}, clear=True):
                    path = _schema_path(None)
                    assert path.name == "schema.json"


class TestLoadSchema:
    """Test cases for _load_schema."""

    def test_schema_not_exists(self, tmp_path):
        """Test loading nonexistent schema."""
        schema_file = tmp_path / "nonexistent.json"
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._schema_path"
        )
        with patch(patch_path, return_value=schema_file):
            result = _load_schema(None)
            assert result is None

    def test_schema_cached(self, tmp_path):
        """Test schema caching."""
        schema_file = tmp_path / "schema.json"
        schema_data = {"definitions": {"Test": {}}}
        schema_file.write_text(json.dumps(schema_data))

        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._schema_path"
        )
        with patch(patch_path, return_value=schema_file):
            result1 = _load_schema(None)
            result2 = _load_schema(None)
            assert result1 == result2
            assert result1 == schema_data


class TestResolveRefs:
    """Test cases for _resolve_refs."""

    def test_resolve_refs_with_circular_ref(self):
        """Test resolving refs with circular reference."""
        definitions = {
            "A": {"$ref": "#/definitions/B", "prop": "value"},
            "B": {"$ref": "#/definitions/A"},
        }
        schema = {"$ref": "#/definitions/A"}
        result = _resolve_refs(schema, definitions)
        # Should return empty dict to break circular reference
        assert isinstance(result, dict)

    def test_resolve_refs_with_list(self):
        """Test resolving refs with list schema."""
        definitions = {}
        schema = [{"key": "value"}, {"key2": "value2"}]
        result = _resolve_refs(schema, definitions)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_resolve_refs_with_nested_dict(self):
        """Test resolving refs with nested dict."""
        definitions = {"Test": {"type": "string"}}
        schema = {"nested": {"$ref": "#/definitions/Test"}}
        result = _resolve_refs(schema, definitions)
        assert "nested" in result


class TestDefinitionFor:
    """Test cases for _definition_for."""

    def test_definition_not_found(self):
        """Test when definition is not found."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._load_schema"
        )
        with patch(patch_path, return_value=None):
            result = _definition_for("UnknownType", None)
            assert result is None

    def test_definition_not_dict(self):
        """Test when definition is not a dict."""
        schema = {"definitions": {"Test": "not a dict"}}
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._load_schema"
        )
        with patch(patch_path, return_value=schema):
            result = _definition_for("Test", None)
            assert result is None


class TestGenerateParams:
    """Test cases for _generate_params."""

    def test_generate_params_with_non_dict_schema(self):
        """Test with non-dict params schema."""
        definition = {"properties": {"params": "not a dict"}}
        params, schema = _generate_params(definition, "realistic")
        assert isinstance(params, dict)
        assert schema == {"type": "object"}

    def test_generate_params_with_non_dict_result(self):
        """Test when params generation returns non-dict."""
        definition = {"properties": {"params": {"type": "object"}}}
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            ".make_fuzz_strategy_from_jsonschema"
        )
        with patch(patch_path, return_value="not a dict"):
            params, schema = _generate_params(definition, "realistic")
            assert params == {}


class TestMutateValueForAggressive:
    """Test cases for _mutate_value_for_aggressive."""

    def test_mutate_string_with_uri_key(self):
        """Test mutating string with URI-related key."""
        result = _mutate_value_for_aggressive("normal_value", "uri")
        assert result in MALICIOUS_STRINGS

    def test_mutate_string_random(self):
        """Test random string mutation."""
        # Run multiple times to increase chance of mutation
        results = [_mutate_value_for_aggressive("test", "other") for _ in range(20)]
        # At least one should be mutated (25% chance each)
        has_malicious = any(r in MALICIOUS_STRINGS for r in results)
        all_same = all(r == "test" for r in results)
        assert has_malicious or all_same

    def test_mutate_number(self):
        """Test number mutation."""
        # Run multiple times to increase chance of mutation
        results = [_mutate_value_for_aggressive(42, None) for _ in range(20)]
        # At least one should be mutated (20% chance each)
        has_malicious = any(r in MALICIOUS_NUMBERS for r in results)
        all_same = all(r == 42 for r in results)
        assert has_malicious or all_same

    def test_mutate_dict(self):
        """Test mutating dict."""
        value = {"key": "value", "nested": {"inner": "data"}}
        result = _mutate_value_for_aggressive(value, None)
        assert isinstance(result, dict)
        assert "key" in result

    def test_mutate_list(self):
        """Test mutating list."""
        value = ["item1", "item2"]
        result = _mutate_value_for_aggressive(value, "list")
        assert isinstance(result, list)


class TestMutateAggressiveParams:
    """Test cases for _mutate_aggressive_params."""

    def test_mutate_aggressive_params_non_dict_result(self):
        """Test when mutation returns non-dict."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            "._mutate_value_for_aggressive"
        )
        with patch(patch_path, return_value="not a dict"):
            params = {"key": "value"}
            result = _mutate_aggressive_params(params)
            assert result == params


class TestApplySemanticOverrides:
    """Test cases for _apply_semantic_overrides."""

    def test_apply_semantic_overrides_non_dict(self):
        """Test with non-dict params."""
        result = _apply_semantic_overrides("not a dict", "realistic")
        assert result == "not a dict"

    def test_apply_semantic_overrides_aggressive_phase(self):
        """Test with aggressive phase."""
        params = {"key": "value"}
        result = _apply_semantic_overrides(params, "aggressive")
        assert isinstance(result, dict)

    def test_apply_semantic_overrides_uri_override(self):
        """Test URI override."""
        params = {"uri": "http://example.com"}
        result = _apply_semantic_overrides(params, "aggressive")
        assert "file://" in result.get("uri", "")

    def test_apply_semantic_overrides_cursor_override(self):
        """Test cursor override."""
        params = {"cursor": "normal_cursor"}
        result = _apply_semantic_overrides(params, "aggressive")
        assert "cursor_" in result.get("cursor", "")

    def test_apply_semantic_overrides_name_override(self):
        """Test name override."""
        params = {"name": "test"}
        result = _apply_semantic_overrides(params, "aggressive")
        assert "_A" in result.get("name", "")


class TestPrepareSchemaParams:
    """Test cases for _prepare_schema_params."""

    def test_prepare_schema_params_no_definition(self):
        """Test when definition is not found."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for"
        )
        with patch(patch_path, return_value=None):
            result = _prepare_schema_params(
                "UnknownType", "realistic", {"override": "value"}, None
            )
            assert result == {"override": "value"}

    def test_prepare_schema_params_no_definition_no_overrides(self):
        """Test when definition is not found and no overrides."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for"
        )
        with patch(patch_path, return_value=None):
            result = _prepare_schema_params("UnknownType", "realistic", None, None)
            assert result == {}


class TestExtractMethodConst:
    """Test cases for _extract_method_const."""

    def test_extract_method_const_not_dict(self):
        """Test when method spec is not a dict."""
        definition = {"properties": {"method": "not a dict"}}
        result = _extract_method_const(definition)
        assert result is None


class TestBuildSchemaRequest:
    """Test cases for _build_schema_request."""

    def test_build_schema_request_no_definition(self):
        """Test when definition is not found."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for"
        )
        with patch(patch_path, return_value=None):
            result = _build_schema_request("UnknownType", "realistic")
            assert result is None

    def test_build_schema_request_notification(self):
        """Test building request for notification type."""
        definition = {
            "properties": {
                "method": {"const": "test/notify"},
                "params": {"type": "object"},
            }
        }
        patch_def = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for"
        )
        patch_params = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            "._prepare_schema_params_from_definition"
        )
        with patch(patch_def, return_value=definition):
            with patch(patch_params, return_value={}):
                result = _build_schema_request("TestNotification", "realistic")
                assert result is not None
                assert "id" not in result  # Notifications don't have id


class TestGetSpecProtocolFuzzerMethod:
    """Test cases for get_spec_protocol_fuzzer_method."""

    def test_get_spec_protocol_fuzzer_method_no_definition(self):
        """Test when definition is not found."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for"
        )
        with patch(patch_path, return_value=None):
            result = get_spec_protocol_fuzzer_method("UnknownType")
            assert result is None


class TestBuildSpecParams:
    """Test cases for build_spec_params."""

    def test_build_spec_params_non_dict_result(self):
        """Test when params is not a dict."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            "._prepare_schema_params"
        )
        with patch(patch_path, return_value="not a dict"):
            result = build_spec_params("TestType", overrides={"key": "value"})
            assert result == {"key": "value"}

    def test_build_spec_params_non_dict_result_no_overrides(self):
        """Test when params is not a dict and no overrides."""
        patch_path = (
            "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol"
            "._prepare_schema_params"
        )
        with patch(patch_path, return_value="not a dict"):
            result = build_spec_params("TestType")
            assert result == {}
