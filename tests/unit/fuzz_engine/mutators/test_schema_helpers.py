from __future__ import annotations

from mcp_fuzzer.fuzz_engine.mutators.strategies import schema_helpers


def test_apply_schema_edge_cases_preserves_existing_value():
    schema = {"type": "string"}
    assert (
        schema_helpers.apply_schema_edge_cases(
            "already", schema, phase="aggressive", key="name"
        )
        == "already"
    )


def test_apply_schema_edge_cases_array_honors_length_constraints():
    schema = {
        "type": "array",
        "minItems": 3,
        "maxItems": 5,
        "items": {"type": "integer", "minimum": 1, "maximum": 3},
    }
    result = schema_helpers.apply_schema_edge_cases(None, schema, phase="aggressive")
    assert isinstance(result, list)
    assert 3 <= len(result) <= 5
    assert all(isinstance(item, int) for item in result)


def test_apply_schema_edge_cases_object_adds_required_and_skips_extra():
    schema = {
        "type": "object",
        "properties": {
            "foo": {"type": "integer", "minimum": 1, "maximum": 2},
        },
        "required": ["foo"],
    }
    value = {}
    result = schema_helpers.apply_schema_edge_cases(value, schema, phase="aggressive")
    # In aggressive mode, off-by-one violations (3 = max+1) are valid
    assert result["foo"] in {1, 2, 3, 0}
    # When we already have a field, extra fields should not be injected
    result_with_value = schema_helpers.apply_schema_edge_cases(
        {"foo": 1}, schema, phase="aggressive"
    )
    assert set(result_with_value) == {"foo"}


def test_apply_schema_edge_cases_string_formats():
    uri_value = schema_helpers.apply_schema_edge_cases(
        None, {"type": "string"}, phase="aggressive", key="resourceURI"
    )
    assert uri_value.startswith("file:///")
    email_value = schema_helpers.apply_schema_edge_cases(
        None, {"type": "string", "format": "email"}, phase="aggressive", key="email"
    )
    assert "@" in email_value


def test_apply_schema_edge_cases_integer_exclusive_maximum_and_multiple_of():
    schema = {
        "type": "integer",
        "maximum": 10,
        "exclusiveMaximum": True,
        "multipleOf": 2,
    }
    result = schema_helpers.apply_schema_edge_cases(None, schema, phase="aggressive")
    assert isinstance(result, int)
    assert result < 10
    assert result % 2 == 0


def test_apply_schema_edge_cases_no_aggressive_does_nothing():
    schema = {"type": "integer", "maximum": 5}
    assert schema_helpers.apply_schema_edge_cases(
        None, schema, phase="realistic"
    ) is None


def test_edge_string_pattern_and_semantics():
    string_schema = {
        "type": "string",
        "minLength": 5,
        "maxLength": 10,
        "pattern": "^[a-zA-Z0-9]+$",
    }
    value = schema_helpers._edge_string(string_schema, key="identifier")
    assert 5 <= len(value) <= 10
    # Pattern matching uses lowercase alphanumeric fill
    assert value.islower() or value.isalnum()
    assert value[:3] == "aaa"

    uri_schema = {"type": "string"}
    uri = schema_helpers._edge_string(uri_schema, key="resourceURI")
    assert uri.startswith("file:///tmp")

    fuzzy_schema = {"type": "string", "minLength": 1, "maxLength": 1}
    short = schema_helpers._edge_string(fuzzy_schema, key="tone")
    assert len(short) >= 1


def test_edge_number_handles_minimum_and_exclusive_minimum():
    schema = {
        "type": "number",
        "minimum": -5,
        "exclusiveMinimum": True,
    }
    value = schema_helpers._edge_number(schema, integer=False)
    # In aggressive mode, _edge_number may generate values that violate bounds
    # The value should be near the boundary (either valid or off-by-one)
    assert -6 < value < 0  # Near the boundary

    schema["maximum"] = 2
    schema["exclusiveMaximum"] = True
    value = schema_helpers._edge_number(schema, integer=False)
    # Value should be near the maximum boundary
    assert -6 < value < 3


def test_edge_array_extra_properties_respected():
    schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 4,
    }
    arr = schema_helpers._edge_array([], schema, phase="aggressive", key="tags")
    assert len(arr) >= 2
    assert all(isinstance(item, str) for item in arr)

    schema["items"] = [{"type": "string"}, {"type": "integer"}]
    arr = schema_helpers._edge_array([], schema, phase="aggressive", key="mixed")
    assert 2 <= len(arr) <= 4
    assert isinstance(arr[1], int)


def test_edge_object_additional_properties_when_empty():
    schema = {
        "type": "object",
        "properties": {},
    }
    obj = schema_helpers._edge_object({}, schema, phase="aggressive", key="payload")
    assert "extra_field_0" in obj
    assert "extra_field_1" in obj

    schema["additionalProperties"] = {"type": "string", "format": "uri"}
    obj = schema_helpers._edge_object({}, schema, phase="aggressive", key="payload")
    assert "extra_field_0" in obj
    assert obj["extra_field_0"].startswith("file:///")
