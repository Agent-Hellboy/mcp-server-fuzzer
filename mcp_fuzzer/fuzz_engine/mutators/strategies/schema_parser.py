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
from typing import Any

# Maximum depth for recursive parsing
MAX_RECURSION_DEPTH = 5


def _merge_allOf(schemas: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Deep merge for allOf schemas.

    Combines properties and required fields, intersects types,
    and applies the most restrictive constraints (max of minimums, min of maximums).
    """
    merged: dict[str, Any] = {}
    props: dict[str, Any] = {}
    required: list[str] = []
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
    schema: dict[str, Any],
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
        return const_val

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


def _handle_enum(enum_values: list[Any], phase: str) -> Any:
    """Handle enum values in schema."""
    return random.choice(enum_values)


def _handle_object_type(
    schema: dict[str, Any], phase: str, recursion_depth: int
) -> dict[str, Any]:
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

    return result


def _handle_array_type(
    schema: dict[str, Any], phase: str, recursion_depth: int
) -> list[Any]:
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
        # In aggressive mode, stay within schema bounds but use edges
        max_items_cap = min(max_items, 100)
        if random.random() < 0.7:
            array_size = random.randint(min_items, max_items_cap)
        else:
            array_size = random.choice([min_items, max_items_cap])

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


def _handle_string_type(schema: dict[str, Any], phase: str) -> str:
    """Handle string type schema."""
    from .interesting_values import (
        get_realistic_boundary_string,
        get_payload_within_length,
        UNICODE_TRICKS,
    )

    # Handle string constraints with conservative defaults
    min_length = max(0, int(schema.get("minLength", 0)))
    max_length = int(schema.get("maxLength", 50))  # Conservative default (was 100)
    if max_length < min_length:
        max_length = min_length
    pattern = schema.get("pattern")
    format_type = schema.get("format")

    # Handle specific string formats
    if isinstance(format_type, str):
        normalized = format_type.strip().lower()
        if normalized:
            return _handle_string_format(normalized, phase)

    # Handle pattern constraint
    if pattern:
        try:
            # Try to generate a string matching the pattern
            # This is a simplified approach - for complex patterns,
            # a more sophisticated regex generator would be needed
            return _generate_string_from_pattern(pattern, min_length, max_length)
        except Exception:  # Handle specific exceptions when possible
            # Fallback if pattern generation fails
            pass

    def _enforce_length(value: str) -> str:
        if len(value) < min_length:
            value = value + "a" * (min_length - len(value))
        if len(value) > max_length:
            value = value[:max_length]
        return value

    # Generate string based on phase
    if phase == "realistic":
        # Generate boundary-length strings for testing
        return get_realistic_boundary_string(min_length, max_length)
    else:
        # In aggressive mode, use constraint-aware attack payloads
        strategies = ["sql", "xss", "path", "unicode", "mixed"]
        strategy = random.choice(strategies)

        if strategy == "sql":
            payload = get_payload_within_length(max_length, "sql")
        elif strategy == "xss":
            payload = get_payload_within_length(max_length, "xss")
        elif strategy == "path":
            payload = get_payload_within_length(max_length, "path")
        elif strategy == "unicode":
            # Embed unicode trick in normal-looking string
            base = "test" + random.choice(UNICODE_TRICKS) + "value"
            payload = base
        else:
            # Mixed special characters
            chars = string.ascii_letters + string.digits + "!@#$%"
            length = random.randint(min_length, min(max_length, 30))
            payload = "".join(random.choice(chars) for _ in range(length))

        return _enforce_length(payload)


def _handle_string_format(format_type: str, phase: str) -> str:
    """Handle specific string formats."""
    if format_type == "date-time":
        # ISO-8601 date-time format
        return datetime.now(timezone.utc).isoformat()

    elif format_type == "date":
        # ISO-8601 date format
        return datetime.now(timezone.utc).date().isoformat()

    elif format_type == "uuid":
        # UUID format
        import uuid

        return str(uuid.uuid4())

    elif format_type == "email":
        # Email format
        domains = ["example.com", "test.org", "mail.net", "domain.io"]
        username = "".join(random.choices(string.ascii_lowercase, k=12))
        domain = random.choice(domains)
        return f"{username}@{domain}"

    elif format_type == "uri":
        # URI format
        schemes = ["http", "https"]
        domains = ["example.com", "test.org", "api.domain.io"]
        paths = ["", "/api", "/v1/resources", "/users/123", "/a" * 10]
        scheme = random.choice(schemes)
        domain = random.choice(domains)
        path = random.choice(paths)
        return f"{scheme}://{domain}{path}"
    elif format_type == "time":
        # RFC 3339 time format (HH:MM:SS)
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        return f"{hour:02d}:{minute:02d}:{second:02d}"
    elif format_type == "ipv4":
        # IPv4 format
        def _ipv4() -> str:
            return ".".join(str(random.randint(0, 255)) for _ in range(4))

        return _ipv4()

    elif format_type == "ipv6":
        # IPv6 format
        def _ipv6() -> str:
            groups = [f"{random.randint(0, 0xFFFF):x}" for _ in range(8)]
            return ":".join(groups)

        return _ipv6()

    elif format_type == "hostname":
        # Hostname format (RFC 1123)
        domains = [
            "example.com",
            "test.org",
            "localhost",
            "api.example.com",
            "subdomain.test.org",
        ]
        return random.choice(domains)

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


def _handle_integer_type(schema: dict[str, Any], phase: str) -> int:
    """Handle integer type schema."""
    from .interesting_values import (
        BOUNDARY_INTS_MEDIUM,
        get_off_by_one_int,
        get_realistic_boundary_int,
    )

    # Handle integer constraints with conservative defaults (was +/-1M)
    minimum = schema.get("minimum", -1000)
    maximum = schema.get("maximum", 1000)
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
        # Generate boundary values for testing
        value = get_realistic_boundary_int(minimum, maximum)
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
        # In aggressive mode, mix boundary coverage with off-by-one/overflow
        roll = random.random()
        if roll < 0.4:
            strategy = "off_by_one"
        elif roll < 0.6:
            strategy = "overflow"
        else:
            strategy = "boundary"

        if strategy == "off_by_one":
            # Off-by-one violation
            if schema.get("maximum") is not None:
                value = get_off_by_one_int(maximum=int(schema["maximum"]))
            elif schema.get("minimum") is not None:
                value = get_off_by_one_int(minimum=int(schema["minimum"]))
            else:
                value = get_off_by_one_int(maximum=maximum)
        elif strategy == "overflow":
            # Integer overflow values
            overflow_values = [2147483648, -2147483649, 9223372036854775808]
            value = random.choice(overflow_values)
        else:
            # Boundary values within range
            boundary_values = [minimum, maximum, 0, -1, 1] + BOUNDARY_INTS_MEDIUM
            valid = [v for v in boundary_values if minimum <= v <= maximum]
            value = random.choice(valid) if valid else random.randint(minimum, maximum)

        if multiple_of:
            try:
                m = int(multiple_of)
                if m > 0:
                    start = ((minimum + (m - 1)) // m) * m
                    if start <= maximum:
                        kmax = (maximum - start) // m
                        value = start + m * random.randint(0, kmax)
            except Exception:
                pass
        return int(value)


def _handle_number_type(schema: dict[str, Any], phase: str) -> float:
    """Handle number type schema."""
    from .interesting_values import SPECIAL_FLOATS

    # Handle number constraints with conservative defaults (was +/-1M)
    minimum = schema.get("minimum", -1000.0)
    maximum = schema.get("maximum", 1000.0)
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
        # Generate boundary float values
        boundaries = [minimum, maximum, (minimum + maximum) / 2, 0.0, 1.0, -1.0]
        valid = [v for v in boundaries if minimum <= v <= maximum]
        value = random.choice(valid) if valid else random.uniform(minimum, maximum)

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
        # In aggressive mode, prioritize off-by-one and special values
        strategies = ["off_by_one", "special", "boundary"]
        strategy = random.choice(strategies)

        if strategy == "off_by_one":
            # Off-by-one violation
            if schema.get("maximum") is not None:
                value = float(schema["maximum"]) + 0.001
            elif schema.get("minimum") is not None:
                value = float(schema["minimum"]) - 0.001
            else:
                value = maximum + 0.001
        elif strategy == "special":
            # Special float values
            value = random.choice(SPECIAL_FLOATS)
        else:
            # Boundary values
            boundaries = [minimum, maximum, 0.0, -0.0, 1.0, -1.0]
            valid = [v for v in boundaries if minimum <= v <= maximum]
            value = random.choice(valid) if valid else random.uniform(minimum, maximum)

        if multiple_of:
            try:
                m = float(multiple_of)
                if m > 0:
                    import math

                    k = round(value / m)
                    candidate = k * m
                    if minimum <= candidate <= maximum:
                        value = candidate
            except Exception:
                pass

        return float(value)


def _handle_boolean_type(phase: str) -> bool:
    """Handle boolean type schema."""
    return random.choice([True, False])


def _generate_default_value(phase: str) -> Any:
    """Generate a default value when schema type is unknown."""
    return random.choice(["default_value", 123, True, [], {}])
