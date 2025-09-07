#!/usr/bin/env python3
"""
JSON Schema Parser for Fuzzing Strategies

This module provides comprehensive support for parsing JSON Schema definitions
and generating appropriate test data based on the schema specifications. It handles
all standard JSON Schema types, constraints, and combinations including:

- Basic types: string, number, integer, boolean, array, object, null
- String constraints: minLength, maxLength, pattern, format
- Number/Integer constraints: minimum, maximum, exclusiveMinimum,
  exclusiveMaximum, multipleOf
- Array constraints: minItems, maxItems, uniqueItems
- Object constraints: required properties and minProperties
- Schema combinations: oneOf, anyOf, allOf
- Enums and constants

The module supports both "realistic" and "aggressive" fuzzing strategies, where
realistic mode generates valid data conforming to the schema, while aggressive
mode intentionally generates edge cases and invalid data to test error handling.
"""

import random
import string
from datetime import datetime, timezone
from typing import Any, Dict, List

# Maximum depth for recursive parsing
MAX_RECURSION_DEPTH = 5


def _merge_allOf(schemas: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Deep merge for allOf schemas.

    Combines properties and required fields, intersects types,
    and applies the most restrictive constraints (max of minimums, min of maximums).
    """
    merged: Dict[str, Any] = {}
    props: Dict[str, Any] = {}
    required: List[str] = []
    merged_types = None  # track intersection of declared types

    # Track min/max constraint values
    min_constraints = {
        "minLength": None,
        "minItems": None,
        "minProperties": None,
        "minimum": None,
        "exclusiveMinimum": None,
    }
    max_constraints = {
        "maxLength": None,
        "maxItems": None,
        "maxProperties": None,
        "maximum": None,
        "exclusiveMaximum": None,
    }

    for s in schemas:
        # Merge properties
        if "properties" in s and isinstance(s["properties"], dict):
            props.update(s["properties"])

        # Merge required fields
        if "required" in s and isinstance(s["required"], list):
            required.extend([r for r in s["required"] if isinstance(r, str)])

        # Intersect types
        t = s.get("type")
        if t is not None:
            tset = set(t if isinstance(t, list) else [t])
            merged_types = tset if merged_types is None else (merged_types & tset)

        # Handle const values
        if "const" in s:
            merged["const"] = s["const"]

        # Track min constraints (take maximum value)
        for key in min_constraints:
            if key in s:
                current = min_constraints[key]
                new_val = s[key]
                if current is None or (new_val is not None and new_val > current):
                    min_constraints[key] = new_val

        # Track max constraints (take minimum value)
        for key in max_constraints:
            if key in s:
                current = max_constraints[key]
                new_val = s[key]
                if current is None or (new_val is not None and new_val < current):
                    max_constraints[key] = new_val

        # Copy other fields (non-constraint)
        for k, v in s.items():
            if (
                k not in ("properties", "required", "type", "const")
                and k not in min_constraints
                and k not in max_constraints
            ):
                merged[k] = v if k not in merged else merged[k]

    # Apply merged properties
    if props:
        merged["properties"] = props

    # Apply merged required fields
    if required:
        merged["required"] = sorted(set(required))

    # Apply merged types
    if merged_types:
        if len(merged_types) > 1:
            merged["type"] = list(merged_types)
        else:
            merged["type"] = next(iter(merged_types))

    # Apply min constraints
    for key, value in min_constraints.items():
        if value is not None:
            merged[key] = value

    # Apply max constraints
    for key, value in max_constraints.items():
        if value is not None:
            merged[key] = value

    return merged


def make_fuzz_strategy_from_jsonschema(
    schema: Dict[str, Any],
    phase: str = "realistic",
    recursion_depth: int = 0,
) -> Any:
    """
    Create a fuzzing strategy based on a JSON Schema.

    Args:
        schema: JSON Schema object
        phase: 'realistic' or 'aggressive'
        recursion_depth: Current recursion depth for nested schemas

    Returns:
        Generated object based on the schema
    """
    # Prevent excessive recursion (respect declared type when possible)
    if recursion_depth > MAX_RECURSION_DEPTH:
        t = schema.get("type")
        fallback_by_type = {
            "object": {},
            "array": [],
            "string": "",
            "integer": 0,
            "number": 0.0,
            "boolean": False,
            "null": None,
        }
        if isinstance(t, list) and t:
            t = t[0]
        return fallback_by_type.get(t, None)

    # Handle schema combinations (oneOf, anyOf, allOf)
    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        # Pick one schema from the oneOf list
        sub_schema = random.choice(schema["oneOf"])
        return make_fuzz_strategy_from_jsonschema(
            sub_schema, phase, recursion_depth + 1
        )

    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        # Pick one schema from the anyOf list
        sub_schema = random.choice(schema["anyOf"])
        return make_fuzz_strategy_from_jsonschema(
            sub_schema, phase, recursion_depth + 1
        )

    if "allOf" in schema and isinstance(schema["allOf"], list):
        # Merge all schemas in the allOf list
        merged_schema = _merge_allOf(schema["allOf"])
        return make_fuzz_strategy_from_jsonschema(
            merged_schema, phase, recursion_depth + 1
        )

    # Handle different schema types
    schema_type = schema.get("type")

    # Handle enums first as they override other type constraints
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return _handle_enum(schema["enum"], phase)

    # Handle const values
    if "const" in schema:
        const_val = schema["const"]
        if phase == "realistic" or random.random() < 0.7:
            return const_val
        # Aggressive: sometimes violate const intentionally
        alt = _generate_default_value("aggressive")
        return alt if alt != const_val else _generate_default_value("aggressive")

    # Handle different types
    if schema_type == "object" or "properties" in schema:
        return _handle_object_type(schema, phase, recursion_depth)
    elif schema_type == "array":
        return _handle_array_type(schema, phase, recursion_depth)
    elif schema_type == "string":
        return _handle_string_type(schema, phase)
    elif schema_type == "integer":
        return _handle_integer_type(schema, phase)
    elif schema_type == "number":
        return _handle_number_type(schema, phase)
    elif schema_type == "boolean":
        return _handle_boolean_type(phase)
    elif schema_type == "null":
        return None

    # Handle schemas with multiple types
    if isinstance(schema_type, list) and schema_type:
        chosen_type = random.choice(schema_type)
        # Create a new schema with just the chosen type
        new_schema = schema.copy()
        new_schema["type"] = chosen_type
        return make_fuzz_strategy_from_jsonschema(
            new_schema, phase, recursion_depth + 1
        )

    # Default fallback
    return _generate_default_value(phase)


def _handle_enum(enum_values: List[Any], phase: str) -> Any:
    """Handle enum values in schema."""
    if phase == "realistic":
        # In realistic mode, simply choose from the enum values
        return random.choice(enum_values)
    else:
        # In aggressive mode, sometimes return valid enum values,
        # sometimes return invalid values to test validation
        if random.random() < 0.7:  # 70% chance of valid value
            return random.choice(enum_values)
        else:
            # Generate an invalid value based on the type of the first enum value
            if enum_values and isinstance(enum_values[0], str):
                # Generate a realistic-looking invalid string
                invalid_options = [
                    "INVALID_" + "".join(random.choices(string.ascii_letters, k=8)),
                    "not-a-valid-option",
                    "unknown_value",
                    "",  # Empty string
                    " " * random.randint(1, 10),  # Whitespace
                    "123invalid",  # Mixed alphanumeric
                ]
                return random.choice(invalid_options)
            elif enum_values and isinstance(enum_values[0], int):
                # Generate a number not in the enum
                all_values = set(enum_values)
                value = random.randint(-1000000, 1000000)
                while value in all_values:
                    value = random.randint(-1000000, 1000000)
                return value
            else:
                return "INVALID_ENUM_VALUE"


def _handle_object_type(
    schema: Dict[str, Any], phase: str, recursion_depth: int
) -> Dict[str, Any]:
    """Handle object type schema."""
    result = {}

    # Get properties
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    # Handle property constraints
    min_properties = schema.get("minProperties", 0)
    # We don't need to explicitly use max_properties as we're not
    # enforcing a maximum number of properties in the generated objects

    # Process each property
    for prop_name, prop_schema in properties.items():
        # For required properties or by chance for optional ones
        # (lower probability in realistic mode)
        chance = 0.3 if phase == "realistic" else 0.8
        if prop_name in required or random.random() < chance:
            result[prop_name] = make_fuzz_strategy_from_jsonschema(
                prop_schema, phase, recursion_depth + 1
            )

    # Ensure we meet minProperties constraint
    if len(result) < min_properties:
        # Respect additionalProperties; if false, do not synthesize extras
        allow_additional = schema.get("additionalProperties", True) is not False
        if allow_additional:
            additional_count = min_properties - len(result)
            for i in range(additional_count):
                prop_name = f"additional_prop_{i}"
                result[prop_name] = _generate_default_value(phase)

    # In aggressive mode, sometimes add extra properties (if allowed)
    if (
        phase == "aggressive"
        and random.random() < 0.3
        and schema.get("additionalProperties", True) is not False
    ):
        # Add some potentially problematic properties
        extra_props = {
            "__proto__": {"isAdmin": True},
            "constructor": {"prototype": {"isAdmin": True}},
            "eval": "console.log('code injection')",
        }
        result.update(
            random.sample(
                extra_props.items(), k=min(len(extra_props), random.randint(1, 3))
            )
        )

    return result


def _handle_array_type(
    schema: Dict[str, Any], phase: str, recursion_depth: int
) -> List[Any]:
    """Handle array type schema."""
    items_schema = schema.get("items", {})

    # Tuple validation: items is a list of schemas (positional)
    if isinstance(items_schema, list):
        return [
            make_fuzz_strategy_from_jsonschema(sub, phase, recursion_depth + 1)
            for sub in items_schema
        ]

    # If this is an array property without items specification,
    # generate an array of simple values
    if not items_schema:
        return [_generate_default_value(phase) for _ in range(random.randint(1, 3))]

    # Handle array constraints
    min_items = max(0, int(schema.get("minItems", 0)))
    max_items = int(schema.get("maxItems", 10))  # Default to reasonable max
    if max_items < min_items:
        max_items = min_items
    unique_items = schema.get("uniqueItems", False)

    # Determine array size
    if phase == "realistic":
        # In realistic mode, use smaller, more reasonable array sizes
        hi = max(min(max_items, 3), min_items)
        array_size = random.randint(min_items, hi)
    else:
        # In aggressive mode, sometimes use edge cases
        if random.random() < 0.7:
            array_size = random.randint(min_items, min(max_items, 10))
        else:
            # Edge cases: empty, minimum, maximum, or very large
            array_size = random.choice(
                [
                    0,  # Empty (might violate minItems)
                    min_items,  # Minimum allowed
                    max_items,  # Maximum allowed
                    min(max_items, 1000),  # Potentially large array
                ]
            )

    # Generate array items
    result = []
    seen_values = set()  # For uniqueItems constraint

    for _ in range(array_size):
        # Generate item based on items schema
        item = make_fuzz_strategy_from_jsonschema(
            items_schema, phase, recursion_depth + 1
        )

        # Handle uniqueItems constraint
        if unique_items:
            # For simple types, ensure uniqueness
            import json as _json

            attempts = 0
            while attempts < 10:
                try:
                    item_hash = _json.dumps(item, sort_keys=True, default=str)
                except Exception:
                    # Fallback to repr if dumps fails
                    item_hash = repr(item)
                if item_hash not in seen_values:
                    seen_values.add(item_hash)
                    break
                item = make_fuzz_strategy_from_jsonschema(
                    items_schema, phase, recursion_depth + 1
                )
                attempts += 1

        result.append(item)

    return result


def _handle_string_type(schema: Dict[str, Any], phase: str) -> str:
    """Handle string type schema."""
    # Handle string constraints
    min_length = max(0, int(schema.get("minLength", 0)))
    max_length = int(schema.get("maxLength", 100))
    if max_length < min_length:
        max_length = min_length
    pattern = schema.get("pattern")
    format_type = schema.get("format")

    # Handle specific string formats
    if format_type:
        return _handle_string_format(format_type, phase)

    # Handle pattern constraint
    if pattern and phase == "realistic":
        try:
            # Try to generate a string matching the pattern
            # This is a simplified approach - for complex patterns,
            # a more sophisticated regex generator would be needed
            return _generate_string_from_pattern(pattern, min_length, max_length)
        except Exception:  # Handle specific exceptions when possible
            # Fallback if pattern generation fails
            pass

    # Generate string based on phase
    if phase == "realistic":
        # Generate a reasonable string with only printable ASCII characters
        length = random.randint(min_length, min(max_length, 50))
        # Use only printable characters, no control characters
        chars = "".join(chr(i) for i in range(32, 127))  # Printable ASCII
        return "".join(random.choice(chars) for _ in range(length))
    else:
        # In aggressive mode, sometimes use edge cases
        if random.random() < 0.7:
            # Normal string with potential edge cases
            length = random.randint(min_length, min(max_length, 100))
            chars = string.ascii_letters + string.digits + string.punctuation
            return "".join(random.choice(chars) for _ in range(length))
        else:
            # Edge cases with safer character sets
            edge_cases = [
                "",  # Empty string (might violate minLength)
                "A" * min_length,  # Minimum length
                "A" * min(max_length, 1000),  # Maximum length (capped)
                "A" * 1000,  # Very long string (reasonable limit)
                "<script>alert('xss')</script>",  # XSS payload
                "' OR '1'='1",  # SQL injection
                "../../../etc/passwd",  # Path traversal
                "\x00\x01\x02\x03",  # Null bytes
                " " * min_length,  # Whitespace
                "mixed123!@#",  # Special characters
            ]
            return random.choice(edge_cases)


def _handle_string_format(format_type: str, phase: str) -> str:
    """Handle specific string formats."""
    if format_type == "date-time":
        # ISO-8601 date-time format
        if phase == "realistic":
            return datetime.now(timezone.utc).isoformat()
        else:
            # Sometimes invalid date-time
            if random.random() < 0.7:
                return datetime.now(timezone.utc).isoformat()
            else:
                return random.choice(
                    [
                        "not-a-date-time",
                        "2024-13-40T25:70:99Z",  # Invalid date/time
                        "2024/01/01 12:00:00",  # Wrong format
                    ]
                )

    elif format_type == "uuid":
        # UUID format
        if phase == "realistic":
            import uuid

            return str(uuid.uuid4())
        else:
            # Sometimes invalid UUID
            if random.random() < 0.7:
                import uuid

                return str(uuid.uuid4())
            else:
                return random.choice(
                    [
                        "not-a-uuid",
                        "12345678-1234-1234-1234-123456789012345",  # Too long
                        "1234-5678-1234-1234-123456789012",  # Wrong format
                    ]
                )

    elif format_type == "email":
        # Email format
        if phase == "realistic":
            domains = ["example.com", "test.org", "mail.net", "domain.io"]
            username = "".join(random.choices(string.ascii_lowercase, k=8))
            domain = random.choice(domains)
            return f"{username}@{domain}"
        else:
            # Sometimes invalid email
            if random.random() < 0.7:
                domains = ["example.com", "test.org", "mail.net", "domain.io"]
                username = "".join(random.choices(string.ascii_lowercase, k=8))
                domain = random.choice(domains)
                return f"{username}@{domain}"
            else:
                return random.choice(
                    [
                        "not-an-email",
                        "missing-at-sign.com",
                        "@missing-username.com",
                        "user@",
                        "user@.com",
                        "user@domain@domain.com",
                    ]
                )

    elif format_type == "uri":
        # URI format
        if phase == "realistic":
            schemes = ["http", "https"]
            domains = ["example.com", "test.org", "api.domain.io"]
            paths = ["", "/api", "/v1/resources", "/users/123"]
            scheme = random.choice(schemes)
            domain = random.choice(domains)
            path = random.choice(paths)
            return f"{scheme}://{domain}{path}"
        else:
            # Sometimes invalid URI
            if random.random() < 0.7:
                schemes = ["http", "https"]
                domains = ["example.com", "test.org", "api.domain.io"]
                paths = ["", "/api", "/v1/resources", "/users/123"]
                scheme = random.choice(schemes)
                domain = random.choice(domains)
                path = random.choice(paths)
                return f"{scheme}://{domain}{path}"
            else:
                return random.choice(
                    [
                        "not-a-uri",
                        "http://",
                        "https://user@:password@",
                        "http://example.com:port",
                        "://missing-scheme.com",
                        "http://<script>alert('xss')</script>",
                    ]
                )

    # Default: treat as regular string
    return _handle_string_type({"type": "string"}, phase)


def _generate_string_from_pattern(
    pattern: str, min_length: int, max_length: int
) -> str:
    """
    Generate a string that matches the given regex pattern.
    This is a simplified implementation for common patterns.
    """
    # Handle some common patterns
    if pattern == "^[a-zA-Z0-9]+$":
        # Alphanumeric
        length = random.randint(min_length, min(max_length, 20))
        return "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(length)
        )

    elif pattern == "^[0-9]+$":
        # Digits only
        length = random.randint(min_length, min(max_length, 10))
        return "".join(random.choice(string.digits) for _ in range(length))

    elif pattern == "^[a-zA-Z]+$":
        # Letters only
        length = random.randint(min_length, min(max_length, 20))
        return "".join(random.choice(string.ascii_letters) for _ in range(length))

    # For more complex patterns, we would need a more sophisticated approach
    # This is just a fallback
    length = random.randint(min_length, min(max_length, 20))
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(length)
    )


def _handle_integer_type(schema: Dict[str, Any], phase: str) -> int:
    """Handle integer type schema."""
    # Handle integer constraints
    minimum = schema.get("minimum", -1000000)
    maximum = schema.get("maximum", 1000000)
    exc_min = schema.get("exclusiveMinimum")
    exc_max = schema.get("exclusiveMaximum")
    multiple_of = schema.get("multipleOf")

    # Handle boolean (draft-04) and numeric (draft-06+) exclusive*
    if isinstance(exc_min, bool) and exc_min:
        minimum += 1
    elif isinstance(exc_min, (int, float)):
        minimum = int(exc_min) + 1
    if isinstance(exc_max, bool) and exc_max:
        maximum -= 1
    elif isinstance(exc_max, (int, float)):
        maximum = int(exc_max) - 1

    # Ensure minimum <= maximum
    if minimum > maximum:
        minimum, maximum = maximum, minimum

    if phase == "realistic":
        # Generate a reasonable integer
        value = random.randint(minimum, maximum)
        if multiple_of:
            try:
                m = int(multiple_of)
                if m > 0:
                    # First multiple >= minimum
                    start = ((minimum + (m - 1)) // m) * m
                    if start > maximum:
                        return value  # no valid multiple; fallback to value in range
                    # Pick a multiple within range
                    kmax = (maximum - start) // m
                    value = start + m * random.randint(0, kmax)
            except Exception:
                pass
        return int(value)
    else:
        # In aggressive mode, sometimes use edge cases
        if random.random() < 0.7:
            # Normal value
            return random.randint(minimum, maximum)
        else:
            # Edge cases
            edge_cases = [
                minimum,  # Minimum value
                maximum,  # Maximum value
                0,  # Zero
                -1,  # Negative one
                1,  # Positive one
                -2147483648,  # INT32_MIN
                2147483647,  # INT32_MAX
                -9223372036854775808,  # INT64_MIN
                9223372036854775807,  # INT64_MAX
            ]

            # Filter out values outside the allowed range
            valid_edge_cases = [v for v in edge_cases if minimum <= v <= maximum]

            if valid_edge_cases:
                return random.choice(valid_edge_cases)
            else:
                return random.randint(minimum, maximum)


def _handle_number_type(schema: Dict[str, Any], phase: str) -> float:
    """Handle number type schema."""
    # Handle number constraints
    minimum = schema.get("minimum", -1000000.0)
    maximum = schema.get("maximum", 1000000.0)
    exc_min = schema.get("exclusiveMinimum")
    exc_max = schema.get("exclusiveMaximum")
    multiple_of = schema.get("multipleOf")

    # Adjust bounds for exclusive constraints
    eps = 1e-9
    if isinstance(exc_min, bool) and exc_min:
        minimum += eps
    elif isinstance(exc_min, (int, float)):
        minimum = float(exc_min) + eps
    if isinstance(exc_max, bool) and exc_max:
        maximum -= eps
    elif isinstance(exc_max, (int, float)):
        maximum = float(exc_max) - eps

    # Ensure minimum <= maximum
    if minimum > maximum:
        minimum, maximum = maximum, minimum

    if phase == "realistic":
        # Generate a reasonable float
        value = random.uniform(minimum, maximum)
        if multiple_of:
            try:
                m = float(multiple_of)
                if m > 0:
                    # Compute index range of valid multiples
                    import math

                    k_start = math.ceil(minimum / m)
                    k_end = math.floor(maximum / m)
                    if k_start <= k_end:
                        # Pick a random multiple within bounds
                        k = random.randint(k_start, k_end)
                        value = k * m
            except Exception:
                # Fallback to the uniform sample if anything goes wrong
                pass
        return float(value)
    else:
        # In aggressive mode, sometimes use edge cases
        if random.random() < 0.7:
            # Normal value
            return random.uniform(minimum, maximum)
        else:
            # Edge cases
            edge_cases = [
                minimum,  # Minimum value
                maximum,  # Maximum value
                0.0,  # Zero
                -0.0,  # Negative zero
                float("inf"),  # Infinity
                float("-inf"),  # Negative infinity
                float("nan"),  # Not a number
            ]

            # Filter out values outside the allowed range
            valid_edge_cases = []
            for v in edge_cases:
                try:
                    if minimum <= v <= maximum:
                        valid_edge_cases.append(v)
                except Exception:  # Handle specific exceptions when possible
                    # Skip values that can't be compared (like NaN)
                    pass

            if valid_edge_cases:
                return random.choice(valid_edge_cases)
            else:
                return random.uniform(minimum, maximum)


def _handle_boolean_type(phase: str) -> bool:
    """Handle boolean type schema."""
    if phase == "realistic":
        # Just a normal boolean
        return random.choice([True, False])
    else:
        # In aggressive mode, sometimes use non-boolean values
        if random.random() < 0.7:
            return random.choice([True, False])
        else:
            return random.choice(
                [
                    None,
                    0,
                    1,
                    "true",
                    "false",
                    "yes",
                    "no",
                ]
            )


def _generate_default_value(phase: str) -> Any:
    """Generate a default value when schema type is unknown."""
    if phase == "realistic":
        # Generate a reasonable default value
        return random.choice(
            [
                "default_value",
                123,
                True,
                [],
                {},
            ]
        )
    else:
        # In aggressive mode, use more varied values
        return random.choice(
            [
                None,
                "",
                0,
                -1,
                "INVALID_VALUE",
                [],
                {},
                "<script>alert('xss')</script>",
            ]
        )
