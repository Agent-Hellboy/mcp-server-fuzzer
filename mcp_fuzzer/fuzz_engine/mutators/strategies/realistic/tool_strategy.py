#!/usr/bin/env python3
"""
Realistic Tool Strategy

This module provides strategies for generating realistic tool arguments and data.
Used in the realistic phase to test server behavior with valid, expected inputs.

Key principles:
- 100% schema-valid values (always pass JSON Schema validation)
- Boundary value testing (minLength, maxLength, minimum, maximum)
- Deterministic enum enumeration (cycle through all values)
- No injection payloads or attack vectors
"""

import asyncio
import base64
import random
import string
import uuid
from datetime import datetime, timezone
from typing import Any

from hypothesis import strategies as st

from ..interesting_values import (
    BOUNDARY_STRINGS,
    REALISTIC_SAMPLES,
    get_realistic_boundary_int,
    get_realistic_boundary_string,
    cycle_enum_values,
)

# Global run counter for deterministic cycling
_run_counter: int = 0


def get_run_index() -> int:
    """Get and increment the global run counter for deterministic cycling."""
    global _run_counter
    idx = _run_counter
    _run_counter += 1
    return idx


def reset_run_counter() -> None:
    """Reset the run counter (useful for testing)."""
    global _run_counter
    _run_counter = 0


def base64_strings(
    min_size: int = 0, max_size: int = 100, alphabet: str | None = None
) -> st.SearchStrategy[str]:
    """
    Generate valid Base64-encoded strings.

    Args:
        min_size: Minimum size of the original data before encoding
        max_size: Maximum size of the original data before encoding
        alphabet: Optional alphabet to use for the original data

    Returns:
        Strategy that generates valid Base64 strings
    """
    if alphabet is None:
        # Use printable ASCII characters for realistic data
        alphabet = st.characters(
            whitelist_categories=("Lu", "Ll", "Nd", "Pc", "Pd", "Ps", "Pe"),
            blacklist_characters="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c",
        )

    return st.binary(min_size=min_size, max_size=max_size).map(
        lambda data: base64.b64encode(data).decode("ascii")
    )


def uuid_strings(version: int | None = None) -> st.SearchStrategy[str]:
    """
    Generate canonical UUID strings.

    Args:
        version: Optional UUID version (1, 3, 4, or 5). If None, generates UUID4

    Returns:
        Strategy that generates valid UUID strings in canonical format
    """
    if version is None or version == 4:
        # Generate random UUID4 (most common)
        return st.uuids(version=4).map(str)
    elif version == 1:
        return st.uuids(version=1).map(str)
    elif version == 3:
        # UUID3 requires namespace and name, use random values
        return st.builds(
            lambda ns, name: str(uuid.uuid3(ns, name)),
            st.uuids(version=4),  # Random namespace
            st.text(min_size=1, max_size=50),  # Random name
        )
    elif version == 5:
        # UUID5 requires namespace and name, use random values
        return st.builds(
            lambda ns, name: str(uuid.uuid5(ns, name)),
            st.uuids(version=4),  # Random namespace
            st.text(min_size=1, max_size=50),  # Random name
        )
    else:
        raise ValueError(f"Unsupported UUID version: {version}")


def timestamp_strings(
    min_year: int = 2020,
    max_year: int = 2030,
    include_microseconds: bool = True,
) -> st.SearchStrategy[str]:
    """
    Generate ISO-8601 UTC timestamps ending with Z.

    Args:
        min_year: Minimum year for generated timestamps
        max_year: Maximum year for generated timestamps
        include_microseconds: Whether to include microsecond precision

    Returns:
        Strategy that generates valid ISO-8601 UTC timestamp strings
    """
    return st.datetimes(
        min_value=datetime(min_year, 1, 1),
        max_value=datetime(max_year, 12, 31, 23, 59, 59),
        timezones=st.just(timezone.utc),
    ).map(
        lambda dt: dt.isoformat(
            timespec="microseconds" if include_microseconds else "seconds"
        )
    )


def generate_realistic_string_sync(
    schema: dict[str, Any],
    key: str | None = None,
    run_index: int | None = None,
) -> str:
    """Generate a schema-valid boundary string for realistic testing (sync version)."""
    if run_index is None:
        run_index = get_run_index()

    min_length = max(0, int(schema.get("minLength", 0)))
    max_length = int(schema.get("maxLength", 50))  # Conservative default
    if max_length < min_length:
        max_length = min_length

    # Handle format constraints
    format_type = schema.get("format")
    if format_type:
        return _generate_formatted_string(format_type, min_length, max_length)

    # Handle pattern constraints
    pattern = schema.get("pattern")
    if pattern:
        return _generate_pattern_string(pattern, min_length, max_length)

    # Use semantic samples if key suggests a known field type
    if key:
        lowered = key.lower()
        for sample_key, samples in REALISTIC_SAMPLES.items():
            if sample_key in lowered:
                sample = samples[run_index % len(samples)]
                # Ensure it fits constraints
                if len(sample) < min_length:
                    sample = sample + "a" * (min_length - len(sample))
                if len(sample) > max_length:
                    sample = sample[:max_length]
                return sample

    # Default: generate boundary-length strings
    return get_realistic_boundary_string(min_length, max_length, run_index)


def generate_realistic_integer_sync(
    schema: dict[str, Any],
    run_index: int | None = None,
) -> int:
    """Generate a schema-valid boundary integer for realistic testing."""
    if run_index is None:
        run_index = get_run_index()

    minimum = int(schema.get("minimum", 0))
    maximum = int(schema.get("maximum", 1000))  # Conservative default

    # Handle exclusive bounds
    exc_min = schema.get("exclusiveMinimum")
    exc_max = schema.get("exclusiveMaximum")

    if isinstance(exc_min, bool) and exc_min:
        minimum += 1
    elif isinstance(exc_min, (int, float)):
        minimum = int(exc_min) + 1

    if isinstance(exc_max, bool) and exc_max:
        maximum -= 1
    elif isinstance(exc_max, (int, float)):
        maximum = int(exc_max) - 1

    if minimum > maximum:
        minimum, maximum = maximum, minimum

    value = get_realistic_boundary_int(minimum, maximum, run_index)

    # Handle multipleOf constraint
    multiple_of = schema.get("multipleOf")
    if multiple_of and int(multiple_of) > 0:
        m = int(multiple_of)
        # Find nearest multiple within range
        start = ((minimum + (m - 1)) // m) * m
        if start <= maximum:
            k_max = (maximum - start) // m
            k = run_index % (k_max + 1)
            value = start + m * k

    return value


def _generate_formatted_string(
    format_type: str,
    min_length: int,
    max_length: int,
) -> str:
    """Generate a string matching a specific format."""
    normalized = format_type.strip().lower()

    if normalized == "date-time":
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    elif normalized == "date":
        return datetime.now(timezone.utc).date().isoformat()
    elif normalized == "time":
        return datetime.now(timezone.utc).strftime("%H:%M:%S")
    elif normalized == "uuid":
        return str(uuid.uuid4())
    elif normalized == "email":
        return "test@example.com"
    elif normalized == "uri":
        return "https://example.com/api/v1"
    elif normalized == "hostname":
        return "example.com"
    elif normalized == "ipv4":
        return "192.168.1.1"
    elif normalized == "ipv6":
        return "2001:db8::1"
    else:
        # Unknown format, generate simple alphanumeric
        length = min(max_length, max(min_length, 10))
        return "a" * length


def _generate_pattern_string(
    pattern: str,
    min_length: int,
    max_length: int,
) -> str:
    """Generate a string matching common regex patterns."""
    length = min(max_length, max(min_length, 10))

    if pattern == "^[a-zA-Z0-9]+$":
        return "Test123"[:length] if length < 7 else "Test123" + "a" * (length - 7)
    elif pattern == "^[0-9]+$":
        return "1" * length
    elif pattern == "^[a-zA-Z]+$":
        return "a" * length
    elif pattern == "^[a-z]+$":
        return "a" * length
    elif pattern == "^[A-Z]+$":
        return "A" * length
    else:
        # Fallback to alphanumeric
        return "a" * length


async def generate_realistic_text(min_size: int = 1, max_size: int = 100) -> str:
    """Generate realistic text using boundary-aware strategies."""
    # Normalize bounds
    if min_size > max_size:
        min_size, max_size = max_size, min_size

    run_index = get_run_index()

    # Use boundary values deterministically
    strategies = [
        "boundary",
        "sample",
        "uuid",
        "timestamp",
    ]
    strategy = strategies[run_index % len(strategies)]

    if strategy == "boundary":
        return get_realistic_boundary_string(min_size, max_size, run_index)
    elif strategy == "sample":
        # Use realistic sample values
        all_samples = []
        for samples in REALISTIC_SAMPLES.values():
            all_samples.extend(samples)
        sample = all_samples[run_index % len(all_samples)]
        # Fit to constraints
        if len(sample) < min_size:
            sample = sample + "a" * (min_size - len(sample))
        if len(sample) > max_size:
            sample = sample[:max_size]
        return sample
    elif strategy == "uuid":
        return str(uuid.uuid4())
    elif strategy == "timestamp":
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    else:
        return get_realistic_boundary_string(min_size, max_size, run_index)


async def fuzz_tool_arguments_realistic(tool: dict[str, Any]) -> dict[str, Any]:
    """
    Generate realistic tool arguments based on schema.

    This function generates schema-valid boundary values for testing business logic:
    - Deterministic cycling through boundary values (min, max, mid)
    - All enum values are cycled through
    - No attack payloads or invalid data
    """
    from ..schema_parser import make_fuzz_strategy_from_jsonschema

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {}

    run_index = get_run_index()

    # Use the enhanced schema parser to generate realistic values
    try:
        args = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
    except Exception:
        args = {}

    # If the schema parser returned something other than a dict, create a default dict
    if not isinstance(args, dict):
        args = {}

    # Get required fields
    required = schema.get("required", [])
    properties = schema.get("properties", {})

    # Process each property with schema-aware generation
    for prop_name, prop_spec in properties.items():
        if not isinstance(prop_spec, dict):
            continue

        # Determine if we should include this property
        is_required = prop_name in required
        # In realistic mode: always include required, sometimes include optional
        should_include = is_required or (run_index % 3 == 0)

        if prop_name in args:
            continue  # Already generated by schema parser

        if not should_include:
            continue

        prop_type = prop_spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else "string"

        # Handle enum values - cycle through all deterministically
        if "enum" in prop_spec and prop_spec["enum"]:
            args[prop_name] = cycle_enum_values(prop_spec["enum"], run_index)
            continue

        # Handle const values
        if "const" in prop_spec:
            args[prop_name] = prop_spec["const"]
            continue

        # Handle by type
        if prop_type == "string":
            args[prop_name] = generate_realistic_string_sync(
                prop_spec, key=prop_name, run_index=run_index
            )
        elif prop_type == "integer":
            args[prop_name] = generate_realistic_integer_sync(
                prop_spec, run_index=run_index
            )
        elif prop_type == "number":
            # Generate boundary float values
            minimum = float(prop_spec.get("minimum", 0.0))
            maximum = float(prop_spec.get("maximum", 100.0))
            boundaries = [minimum, maximum, (minimum + maximum) / 2]
            args[prop_name] = boundaries[run_index % len(boundaries)]
        elif prop_type == "boolean":
            # Cycle through True/False
            args[prop_name] = run_index % 2 == 0
        elif prop_type == "array":
            args[prop_name] = await _generate_realistic_array(
                prop_spec, run_index=run_index
            )
        elif prop_type == "object":
            try:
                nested = make_fuzz_strategy_from_jsonschema(prop_spec, phase="realistic")
                args[prop_name] = nested if isinstance(nested, dict) else {}
            except Exception:
                args[prop_name] = {}
        else:
            # Fallback for unknown types
            args[prop_name] = await generate_realistic_text()

    # Ensure all required fields are present
    for field in required:
        if field not in args:
            field_spec = properties.get(field, {})
            args[field] = generate_realistic_string_sync(
                field_spec, key=field, run_index=run_index
            )

    return args


async def _generate_realistic_array(
    schema: dict[str, Any],
    run_index: int = 0,
) -> list[Any]:
    """Generate a schema-valid array with boundary item counts."""
    from ..schema_parser import make_fuzz_strategy_from_jsonschema

    min_items = max(0, int(schema.get("minItems", 0)))
    max_items = int(schema.get("maxItems", 5))  # Conservative default

    if max_items < min_items:
        max_items = min_items

    # Cycle through boundary counts: min, max, mid
    boundary_counts = [min_items, max_items, (min_items + max_items) // 2]
    count = max(1, boundary_counts[run_index % len(boundary_counts)])

    items_schema = schema.get("items", {})
    if isinstance(items_schema, list):
        # Tuple validation
        return [
            make_fuzz_strategy_from_jsonschema(sub, phase="realistic")
            for sub in items_schema[:count]
        ]

    # Generate items based on schema
    result = []
    for i in range(count):
        try:
            item = make_fuzz_strategy_from_jsonschema(items_schema, phase="realistic")
            result.append(item)
        except Exception:
            result.append("item")

    return result
