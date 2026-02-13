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
import math
import random
import re
import string
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from hypothesis import strategies as st

from ..interesting_values import (
    REALISTIC_SAMPLES,
    get_realistic_boundary_int,
    get_realistic_boundary_string,
    cycle_enum_values,
)

# Thread-local run counter for deterministic cycling per thread
_run_counter = threading.local()


def _utc_timestamp() -> str:
    """Return an RFC3339 timestamp in UTC with seconds precision."""
    dt = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return dt.replace("+00:00", "Z")


def get_run_index() -> int:
    """Get and increment the per-thread run counter for deterministic cycling."""
    idx = getattr(_run_counter, "value", 0)
    _run_counter.value = idx + 1
    return idx


def reset_run_counter() -> None:
    """Reset the per-thread run counter (useful for testing)."""
    _run_counter.value = 0


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

    minimum = schema.get("minimum", 0)
    maximum = schema.get("maximum", 1000)  # Conservative default

    if isinstance(minimum, (int, float)):
        minimum = math.ceil(minimum)
    else:
        minimum = 0

    if isinstance(maximum, (int, float)):
        maximum = math.floor(maximum)
    else:
        maximum = 1000

    # Handle exclusive bounds
    exc_min = schema.get("exclusiveMinimum")
    exc_max = schema.get("exclusiveMaximum")

    if isinstance(exc_min, bool) and exc_min:
        minimum += 1
    elif isinstance(exc_min, (int, float)):
        minimum = max(minimum, math.floor(exc_min) + 1)

    if isinstance(exc_max, bool) and exc_max:
        maximum -= 1
    elif isinstance(exc_max, (int, float)):
        maximum = min(maximum, math.ceil(exc_max) - 1)

    if minimum > maximum:
        minimum, maximum = maximum, minimum

    value = get_realistic_boundary_int(minimum, maximum, run_index)

    # Handle multipleOf constraint
    multiple_of = schema.get("multipleOf")
    if isinstance(multiple_of, (int, float)) and float(multiple_of).is_integer():
        m = int(multiple_of)
    else:
        m = None

    if m and m > 0:
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

    def _fits(value: str) -> bool:
        return min_length <= len(value) <= max_length

    def _fallback() -> str:
        return get_realistic_boundary_string(min_length, max_length, 0)

    if normalized == "date-time":
        value = _utc_timestamp()
    elif normalized == "date":
        value = datetime.now(timezone.utc).date().isoformat()
    elif normalized == "time":
        value = datetime.now(timezone.utc).strftime("%H:%M:%S")
    elif normalized == "uuid":
        value = str(uuid.uuid4())
    elif normalized == "email":
        value = "test@example.com"
        if max_length < len(value):
            value = "a@b.co"
        if max_length < len(value):
            return _fallback()
        if len(value) < min_length:
            extra = min_length - len(value)
            local, _, domain = value.partition("@")
            value = f"{local}{'a' * extra}@{domain}"
        if not _fits(value):
            return _fallback()
    elif normalized == "uri":
        value = "https://example.com"
        if max_length < len(value):
            value = "https://a.b"
        if max_length < len(value):
            return _fallback()
        if len(value) < min_length:
            extra = min_length - len(value)
            value = value + "/" + "a" * max(0, extra - 1)
        if not _fits(value):
            return _fallback()
    elif normalized == "hostname":
        value = "example.com"
        if max_length < len(value):
            value = "a.io"
        if max_length < len(value):
            return _fallback()
        if len(value) < min_length:
            value = value + "a" * (min_length - len(value))
        if not _fits(value):
            return _fallback()
    elif normalized == "ipv4":
        value = "192.168.1.1"
    elif normalized == "ipv6":
        value = "2001:db8::1"
    else:
        # Unknown format, generate simple alphanumeric
        length = min(max_length, max(min_length, 10))
        value = "a" * length

    if _fits(value):
        return value

    if normalized in {
        "date-time",
        "date",
        "time",
        "uuid",
        "ipv4",
        "ipv6",
    }:
        return _fallback()

    if len(value) < min_length:
        value = value + "a" * (min_length - len(value))
    if len(value) > max_length:
        value = value[:max_length]
    return value


def _generate_pattern_string(
    pattern: str,
    min_length: int,
    max_length: int,
) -> str:
    """Generate a string matching common regex patterns."""
    length = min(max_length, max(min_length, 10))

    if pattern == "^[a-zA-Z0-9]+$":
        candidate = (
            "Test123"[:length] if length < 7 else "Test123" + "a" * (length - 7)
        )
    elif pattern == "^[0-9]+$":
        candidate = "1" * length
    elif pattern == "^[a-zA-Z]+$":
        candidate = "a" * length
    elif pattern == "^[a-z]+$":
        candidate = "a" * length
    elif pattern == "^[A-Z]+$":
        candidate = "A" * length
    else:
        # Fallback to alphanumeric
        candidate = "a" * length

    try:
        if (
            min_length <= len(candidate) <= max_length
            and re.fullmatch(pattern, candidate) is not None
        ):
            return candidate
    except re.error:
        pass

    return get_realistic_boundary_string(min_length, max_length, 0)


async def generate_realistic_text(min_size: int = 1, max_size: int = 100) -> str:
    """Generate realistic text using mixed deterministic and random strategies."""
    if min_size > max_size:
        min_size, max_size = max_size, min_size

    strategies = [
        "normal",
        "base64",
        "uuid",
        "timestamp",
        "numbers",
        "mixed_alphanumeric",
    ]
    strategy = random.choice(strategies)

    if strategy == "base64":
        loop = asyncio.get_running_loop()

        def _encode() -> str:
            size = random.randint(min_size, max_size)
            data = bytes(random.randint(0, 255) for _ in range(size))
            return base64.b64encode(data).decode("ascii")

        return await loop.run_in_executor(None, _encode)
    if strategy == "uuid":
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: str(uuid.uuid4()))
    if strategy == "timestamp":
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            _utc_timestamp,
        )
    if strategy == "numbers":
        return str(random.randint(0, 1000))
    if strategy == "mixed_alphanumeric":
        length = random.randint(min_size, max_size)
        alphabet = string.ascii_letters + string.digits
        return "".join(random.choice(alphabet) for _ in range(length))

    normal_samples = [
        "Sales Performance Q4",
        "Project Status Update",
        "Weekly Summary",
        "Customer Feedback Report",
    ]
    sample = random.choice(normal_samples)
    if len(sample) < min_size:
        sample = sample + "a" * (min_size - len(sample))
    if len(sample) > max_size:
        sample = sample[:max_size]
    return sample


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

    async def _generate_value(prop_name: str, prop_spec: dict[str, Any]) -> Any:
        prop_type = prop_spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else "string"

        # Handle enum values - cycle through all deterministically
        if "enum" in prop_spec and prop_spec["enum"]:
            return cycle_enum_values(prop_spec["enum"], run_index)

        # Handle const values
        if "const" in prop_spec:
            return prop_spec["const"]

        # Handle by type
        if prop_type == "string":
            return generate_realistic_string_sync(
                prop_spec, key=prop_name, run_index=run_index
            )
        if prop_type == "integer":
            return generate_realistic_integer_sync(prop_spec, run_index=run_index)
        if prop_type == "number":
            try:
                minimum = float(prop_spec.get("minimum", 0.0))
            except (TypeError, ValueError):
                minimum = 0.0
            try:
                maximum = float(prop_spec.get("maximum", 100.0))
            except (TypeError, ValueError):
                maximum = 100.0
            exc_min = prop_spec.get("exclusiveMinimum")
            exc_max = prop_spec.get("exclusiveMaximum")
            if isinstance(exc_min, bool) and exc_min:
                minimum = math.nextafter(minimum, math.inf)
            elif isinstance(exc_min, (int, float)):
                minimum = math.nextafter(float(exc_min), math.inf)
            if isinstance(exc_max, bool) and exc_max:
                maximum = math.nextafter(maximum, -math.inf)
            elif isinstance(exc_max, (int, float)):
                maximum = math.nextafter(float(exc_max), -math.inf)
            if minimum > maximum:
                minimum, maximum = maximum, minimum
            boundaries = [minimum, maximum, (minimum + maximum) / 2]
            multiple_of = prop_spec.get("multipleOf")
            if isinstance(multiple_of, (int, float)) and multiple_of > 0:
                m = float(multiple_of)

                def _normalize(value: float) -> float:
                    snapped = round(value / m) * m
                    if snapped < minimum:
                        snapped = math.ceil(minimum / m) * m
                    if snapped > maximum:
                        snapped = math.floor(maximum / m) * m
                    return snapped

                boundaries = [_normalize(val) for val in boundaries]
            return boundaries[run_index % len(boundaries)]
        if prop_type == "boolean":
            return run_index % 2 == 0
        if prop_type == "array":
            return await _generate_realistic_array(prop_spec, run_index=run_index)
        if prop_type == "object":
            try:
                nested = make_fuzz_strategy_from_jsonschema(
                    prop_spec, phase="realistic"
                )
                return nested if isinstance(nested, dict) else {}
            except Exception:
                return {}

        return await generate_realistic_text()

    # Process each property with schema-aware generation
    for prop_name, prop_spec in properties.items():
        if not isinstance(prop_spec, dict):
            continue

        prop_type = prop_spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else "string"
        is_required = prop_name in required
        should_include = (
            is_required
            or prop_type in {"array", "object"}
            or (prop_type == "string" and "format" in prop_spec)
            or (run_index % 3 == 0)
        )

        if prop_name in args:
            if args[prop_name] is None and prop_type != "null":
                args[prop_name] = await _generate_value(prop_name, prop_spec)
            continue  # Already generated by schema parser

        if not should_include:
            continue

        args[prop_name] = await _generate_value(prop_name, prop_spec)

    # Ensure all required fields are present
    for field in required:
        if field not in args:
            field_spec = properties.get(field, {})
            if isinstance(field_spec, dict):
                args[field] = await _generate_value(field, field_spec)
            else:
                args[field] = await generate_realistic_text()

    return args


async def _generate_realistic_array(
    schema: dict[str, Any],
    run_index: int = 0,
) -> list[Any]:
    """Generate a schema-valid array with randomized item counts."""
    from ..schema_parser import make_fuzz_strategy_from_jsonschema

    min_items = max(0, int(schema.get("minItems", 0)))
    max_items = int(schema.get("maxItems", 5))

    if max_items < min_items:
        max_items = min_items

    if max_items == min_items:
        count = min_items
    else:
        span = max_items - min_items + 1
        count = min_items + (run_index % span)

    items_schema = schema.get("items", {})
    if isinstance(items_schema, list):
        schemas = list(items_schema)
        if not schemas:
            schemas = [{}]
        if count > len(schemas):
            additional_items = schema.get("additionalItems")
            if isinstance(additional_items, dict):
                while len(schemas) < count:
                    schemas.append(additional_items)
            else:
                last = schemas[-1]
                while len(schemas) < count:
                    schemas.append(last)
        return [
            make_fuzz_strategy_from_jsonschema(sub, phase="realistic")
            for sub in schemas[:count]
        ]

    result = []
    item_type = None
    if isinstance(items_schema, dict):
        item_type = items_schema.get("type")

    for _ in range(count):
        try:
            if item_type in {"number", "integer"}:
                value = make_fuzz_strategy_from_jsonschema(
                    items_schema, phase="realistic"
                )
                result.append(value)
            elif item_type == "string":
                result.append(
                    generate_realistic_string_sync(
                        items_schema, run_index=run_index
                    )
                )
            else:
                item = make_fuzz_strategy_from_jsonschema(
                    items_schema, phase="realistic"
                )
                result.append(item)
        except Exception:
            result.append("item")

    return result
