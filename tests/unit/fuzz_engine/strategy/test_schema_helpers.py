"""
Unit tests for schema_helpers.py module.
"""

import pytest
from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_helpers import (
    apply_schema_edge_cases,
    apply_semantic_combos,
)


class TestApplySchemaEdgeCases:
    """Test cases for apply_schema_edge_cases."""

    def test_const_value(self):
        """Test const value is returned."""
        schema = {"const": "fixed_value"}
        result = apply_schema_edge_cases("any", schema, phase="aggressive")
        assert result == "fixed_value"

    def test_enum_value(self):
        """Test enum value is returned."""
        schema = {"enum": ["a", "b", "c"]}
        result = apply_schema_edge_cases("any", schema, phase="aggressive")
        assert result == "c"  # Last enum value

    def test_list_type_schema(self):
        """Test schema with list type."""
        schema = {"type": ["string", "integer"]}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)

    def test_object_schema(self):
        """Test object schema."""
        schema = {"type": "object", "properties": {"name": {"type": "string"}}}
        result = apply_schema_edge_cases({}, schema, phase="aggressive")
        assert isinstance(result, dict)

    def test_array_schema_with_existing_value(self):
        """Test array schema with existing list value."""
        schema = {"type": "array", "items": {"type": "string"}}
        result = apply_schema_edge_cases(["existing"], schema, phase="aggressive")
        assert result == ["existing"]

    def test_array_schema_empty(self):
        """Test array schema without existing value."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 2}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_string_schema_with_value(self):
        """Test string schema with existing value."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases("existing", schema, phase="aggressive")
        assert result == "existing"

    def test_string_schema_without_value(self):
        """Test string schema without value."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)

    def test_integer_schema_with_value(self):
        """Test integer schema with existing value."""
        schema = {"type": "integer"}
        result = apply_schema_edge_cases(42, schema, phase="aggressive")
        assert result == 42

    def test_integer_schema_without_value(self):
        """Test integer schema without value."""
        schema = {"type": "integer"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, int)

    def test_number_schema_with_value(self):
        """Test number schema with existing value."""
        schema = {"type": "number"}
        result = apply_schema_edge_cases(3.14, schema, phase="aggressive")
        assert result == 3.14

    def test_number_schema_without_value(self):
        """Test number schema without value."""
        schema = {"type": "number"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))

    def test_realistic_phase_no_mutation(self):
        """Test realistic phase doesn't mutate."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases("original", schema, phase="realistic")
        assert result == "original"

    def test_non_dict_schema(self):
        """Test non-dict schema."""
        result = apply_schema_edge_cases("value", "not a dict", phase="aggressive")
        assert result == "value"

    def test_object_with_required_properties(self):
        """Test object schema with required properties."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        result = apply_schema_edge_cases({}, schema, phase="aggressive")
        assert "name" in result

    def test_object_with_additional_properties(self):
        """Test object schema with additionalProperties."""
        schema = {
            "type": "object",
            "properties": {},
            "additionalProperties": {"type": "string"},
        }
        result = apply_schema_edge_cases({}, schema, phase="aggressive")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_array_with_max_items_zero(self):
        """Test array schema with maxItems=0."""
        schema = {"type": "array", "items": {"type": "string"}, "maxItems": 0}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert result == []
    
    def test_array_with_max_items_none(self):
        """Test array schema with maxItems=None."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 5}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, list)
        assert len(result) >= 5
    
    def test_array_with_max_items_none_and_length_less_than_min(self):
        """Test array schema with maxItems=None and length < minItems."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 5}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="test")
        assert isinstance(result, list)
        assert len(result) >= 5

    def test_array_with_list_items_schema(self):
        """Test array with list items schema."""
        schema = {
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}],
            "minItems": 3,
        }
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="test")
        assert isinstance(result, list)
        assert len(result) >= 3

    def test_array_focus_key(self):
        """Test array with focus key."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 2}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="focus")
        assert isinstance(result, list)
        assert "correctness" in result or "performance" in result

    def test_array_point_key(self):
        """Test array with point key."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 2}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="point")
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_array_stack_key(self):
        """Test array with stack key."""
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 2}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="stack")
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_string_with_const(self):
        """Test string schema with const."""
        schema = {"type": "string", "const": "fixed"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert result == "fixed"

    def test_string_with_enum(self):
        """Test string schema with enum."""
        schema = {"type": "string", "enum": ["a", "b", "c"]}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert result == "c"

    def test_string_with_enum_non_string(self):
        """Test string schema with enum containing non-string."""
        schema = {"type": "string", "enum": [1, 2, 3]}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert result == "3"

    def test_string_with_max_length_zero(self):
        """Test string schema with maxLength=0."""
        schema = {"type": "string", "maxLength": 0}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert result == ""

    def test_string_with_max_length_less_than_min(self):
        """Test string schema with maxLength < minLength."""
        schema = {"type": "string", "minLength": 10, "maxLength": 5}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)

    def test_string_date_time_format(self):
        """Test string schema with date-time format."""
        schema = {"type": "string", "format": "date-time"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)
        assert "T" in result or "Z" in result

    def test_string_uuid_format(self):
        """Test string schema with uuid format."""
        schema = {"type": "string", "format": "uuid"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)
        assert len(result) == 36

    def test_string_email_format(self):
        """Test string schema with email format."""
        schema = {"type": "string", "format": "email"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)
        assert "@" in result

    def test_string_uri_format(self):
        """Test string schema with uri format."""
        schema = {"type": "string", "format": "uri"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)
        assert "file://" in result

    def test_string_uri_key(self):
        """Test string schema with uri in key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="uri")
        assert isinstance(result, str)
        assert "file://" in result

    def test_string_pattern_numeric(self):
        """Test string schema with numeric pattern."""
        schema = {"type": "string", "pattern": "^[0-9]+$", "maxLength": 10}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)
        assert result.isdigit()

    def test_string_pattern_alphanumeric(self):
        """Test string schema with alphanumeric pattern."""
        schema = {"type": "string", "pattern": "^[a-zA-Z0-9]+$", "maxLength": 10}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, str)

    def test_string_semantic_language_key(self):
        """Test string schema with language key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="language"
        )
        assert isinstance(result, str)

    def test_string_semantic_file_path_key(self):
        """Test string schema with file_path key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="file_path"
        )
        assert isinstance(result, str)

    def test_string_semantic_analysis_key(self):
        """Test string schema with analysis key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="analysis"
        )
        assert isinstance(result, str)

    def test_string_semantic_content_type_key(self):
        """Test string schema with content_type key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="content_type"
        )
        assert isinstance(result, str)

    def test_string_semantic_audience_key(self):
        """Test string schema with audience key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="audience"
        )
        assert isinstance(result, str)

    def test_string_semantic_tone_key(self):
        """Test string schema with tone key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="tone")
        assert result == "technical"

    def test_string_semantic_error_key(self):
        """Test string schema with error key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="error")
        assert isinstance(result, str)

    def test_string_semantic_context_key(self):
        """Test string schema with context key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="context"
        )
        assert isinstance(result, str)

    def test_string_semantic_department_key(self):
        """Test string schema with department key."""
        schema = {"type": "string"}
        result = apply_schema_edge_cases(
            None, schema, phase="aggressive", key="department"
        )
        assert isinstance(result, str)

    def test_number_with_exclusive_minimum(self):
        """Test number schema with exclusiveMinimum."""
        schema = {"type": "number", "exclusiveMinimum": 10}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert result > 10

    def test_number_with_exclusive_maximum(self):
        """Test number schema with exclusiveMaximum."""
        schema = {"type": "number", "exclusiveMaximum": 100}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert result < 100

    def test_number_with_exclusive_minimum_numeric(self):
        """Test number schema with numeric exclusiveMinimum."""
        schema = {"type": "number", "exclusiveMinimum": 10.5}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))

    def test_number_with_multiple_of(self):
        """Test number schema with multipleOf."""
        schema = {"type": "number", "minimum": 10, "maximum": 20, "multipleOf": 3}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert result % 3 == 0

    def test_number_with_multiple_of_adjustment(self):
        """Test number schema with multipleOf requiring adjustment."""
        schema = {"type": "number", "minimum": 10, "maximum": 15, "multipleOf": 7}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert 10 <= result <= 15
    
    def test_number_with_multiple_of_below_minimum(self):
        """Test number schema with multipleOf below minimum."""
        schema = {"type": "number", "minimum": 10, "multipleOf": 3}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert result >= 10
        assert result % 3 == 0
    
    def test_number_with_multiple_of_above_maximum(self):
        """Test number schema with multipleOf above maximum."""
        schema = {"type": "number", "maximum": 15, "multipleOf": 20}
        result = apply_schema_edge_cases(None, schema, phase="aggressive")
        assert isinstance(result, (int, float))
        assert result <= 15
    
    def test_string_resize_short(self):
        """Test string resizing when value is shorter than min_length."""
        from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_helpers import (
            _resize_string,
        )
        result = _resize_string("short", 20, 30)
        assert len(result) >= 20
        assert result.startswith("short")
    
    def test_string_resize_long(self):
        """Test string resizing when value is longer than max_length."""
        from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_helpers import (
            _resize_string,
        )
        result = _resize_string("a" * 50, 10, 20)
        assert len(result) <= 20
    
    def test_build_traversal_uri_short(self):
        """Test _build_traversal_uri with short length."""
        from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_helpers import (
            _build_traversal_uri,
        )
        result = _build_traversal_uri(10)
        assert len(result) == 10
    
    def test_build_traversal_uri_long(self):
        """Test _build_traversal_uri with long length."""
        from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_helpers import (
            _build_traversal_uri,
        )
        result = _build_traversal_uri(200)
        assert len(result) == 200
        assert "file://" in result
    
    def test_object_additional_properties_false(self):
        """Test object schema with additionalProperties=False."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": False,
        }
        result = apply_schema_edge_cases({}, schema, phase="aggressive")
        assert isinstance(result, dict)
        # Should not add extra fields when additionalProperties is False
        assert "name" in result or result == {}
    
    def test_object_additional_properties_dict(self):
        """Test object schema with additionalProperties as dict."""
        schema = {
            "type": "object",
            "properties": {},
            "additionalProperties": {"type": "integer"},
        }
        result = apply_schema_edge_cases({}, schema, phase="aggressive")
        assert isinstance(result, dict)
        # Should add extra fields with integer schema
        if result:
            for key, value in result.items():
                assert isinstance(value, int) or key == "name"
    
    def test_array_items_schema_list_extension(self):
        """Test array with list items schema that needs extension."""
        schema = {
            "type": "array",
            "items": [{"type": "string"}],
            "minItems": 5,  # More than items list length
        }
        result = apply_schema_edge_cases(None, schema, phase="aggressive", key="test")
        assert isinstance(result, list)
        assert len(result) >= 5


class TestApplySemanticCombos:
    """Test cases for apply_semantic_combos."""

    def test_role_admin_reduces_age(self):
        """Test admin role reduces age."""
        patched = {"role": "admin", "age": 25}
        apply_semantic_combos(patched)
        assert patched["age"] <= 17

    def test_role_admin_with_string_age(self):
        """Test admin role with string age."""
        patched = {"role": "admin", "age": "25"}
        apply_semantic_combos(patched)
        assert patched["age"] <= 17

    def test_role_admin_with_invalid_age(self):
        """Test admin role with invalid age."""
        patched = {"role": "admin", "age": "invalid"}
        apply_semantic_combos(patched)
        assert patched["age"] <= 17

    def test_operation_divide_sets_second_zero(self):
        """Test divide operation sets second to zero."""
        patched = {"operation": "divide", "second": 5}
        apply_semantic_combos(patched)
        assert patched["second"] == 0
