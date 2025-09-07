#!/usr/bin/env python3
"""
Realistic Tool Strategy

This module provides strategies for generating realistic tool arguments and data.
Used in the realistic phase to test server behavior with valid, expected inputs.
"""

import asyncio
import base64
import random
import string
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from hypothesis import strategies as st


def base64_strings(
    min_size: int = 0, max_size: int = 100, alphabet: Optional[str] = None
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


def uuid_strings(version: Optional[int] = None) -> st.SearchStrategy[str]:
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


async def generate_realistic_text(min_size: int = 1, max_size: int = 100) -> str:
    """Generate realistic text using custom strategies."""
    # Normalize bounds and cache loop
    if min_size > max_size:
        min_size, max_size = max_size, min_size
    loop = asyncio.get_running_loop()

    strategy = random.choice(
        [
            "normal",
            "base64",
            "uuid",
            "timestamp",
            "numbers",
            "mixed_alphanumeric",
        ]
    )

    if strategy == "normal":
        # Generate more realistic data based on context
        if min_size == 0 and max_size > 50:
            # Likely a title or description field - use realistic text
            realistic_titles = [
                "Sales Performance Q4", "User Growth Metrics", "Revenue Analysis",
                "Customer Satisfaction Survey", "Product Usage Statistics",
                "Market Share Analysis", "Performance Dashboard", "Trend Analysis"
            ]
            return random.choice(realistic_titles)
        else:
            # Use only printable ASCII characters, no control characters
            chars = string.ascii_letters + string.digits + " ._-"
            length = random.randint(min_size, min(max_size, 100))  # Limit max length
            return "".join(random.choice(chars) for _ in range(length))
    elif strategy == "base64":
        # Use asyncio executor to prevent deadlocks
        size_min = max(1, min_size // 2)
        size_max = max(1, max_size // 2)
        if size_min > size_max:
            size_min, size_max = size_max, size_min
        return await loop.run_in_executor(
            None,
            base64_strings(min_size=size_min, max_size=size_max).example,
        )
    elif strategy == "uuid":
        # Use asyncio executor to prevent deadlocks
        return await loop.run_in_executor(None, uuid_strings().example)
    elif strategy == "timestamp":
        # Use asyncio executor to prevent deadlocks
        return await loop.run_in_executor(None, timestamp_strings().example)
    elif strategy == "numbers":
        return str(random.randint(1, 999999))
    elif strategy == "mixed_alphanumeric":
        length = random.randint(min_size, max_size)
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(length))
    else:
        return "realistic_value"


async def fuzz_tool_arguments_realistic(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Generate realistic tool arguments based on schema."""
    from ..schema_parser import make_fuzz_strategy_from_jsonschema

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {}

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

    # Always backfill any missing required fields
    if required:
        for field in required:
            if field not in args:
                args[field] = await generate_realistic_text()

    # Ensure we have at least some arguments
    if schema.get("properties"):
        properties = schema.get("properties", {})

        for prop_name, prop_spec in properties.items():
            # Special handling for array type properties
            if prop_spec.get("type") == "array":
                if prop_name not in args or not isinstance(args[prop_name], list):
                    items_schema = prop_spec.get("items", {})
                    count = random.randint(1, 3)
                    item_type = items_schema.get("type")
                    values: list[Any] = []

                    if item_type == "object":
                        # Generate each object via schema parser to honor constraints
                        for _ in range(count):
                            try:
                                from ..schema_parser import (
                                    make_fuzz_strategy_from_jsonschema as _mk,
                                )

                                val = _mk(items_schema, phase="realistic")
                                values.append(val if isinstance(val, dict) else {})
                            except Exception:
                                values.append({})
                    elif item_type == "integer":
                        minimum = items_schema.get("minimum", -100)
                        maximum = items_schema.get("maximum", 100)
                        values = [
                            random.randint(minimum, maximum) for _ in range(count)
                        ]
                    elif item_type == "number":
                        minimum = items_schema.get("minimum", -100.0)
                        maximum = items_schema.get("maximum", 100.0)
                        values = [
                            round(random.uniform(minimum, maximum), 2)
                            for _ in range(count)
                        ]
                    else:
                        values = [await generate_realistic_text() for _ in range(count)]
                    args[prop_name] = values
            # Special handling for object type properties
            elif prop_spec.get("type") == "object":
                if prop_name not in args or not isinstance(args[prop_name], dict):
                    # Generate nested object via schema parser to honor constraints
                    try:
                        from ..schema_parser import (
                            make_fuzz_strategy_from_jsonschema as _mk,
                        )

                        nested = _mk(prop_spec, phase="realistic")
                        args[prop_name] = nested if isinstance(nested, dict) else {}
                    except Exception:
                        args[prop_name] = {}
            # Special handling for integer type properties
            elif prop_spec.get("type") == "integer":
                # Generate an integer within the specified range
                if prop_name not in args:
                    minimum = prop_spec.get("minimum", -100)
                    maximum = prop_spec.get("maximum", 100)

                    args[prop_name] = random.randint(minimum, maximum)
            # Special handling for number type properties
            elif prop_spec.get("type") == "number":
                # Generate a float within the specified range
                if prop_name not in args:
                    minimum = prop_spec.get("minimum", -100.0)
                    maximum = prop_spec.get("maximum", 100.0)
                    args[prop_name] = round(random.uniform(minimum, maximum), 2)
            # Special handling for boolean type properties
            elif prop_spec.get("type") == "boolean":
                if prop_name not in args:
                    args[prop_name] = random.choice([True, False])
            # Special handling for string format types
            elif prop_spec.get("type") == "string" and prop_spec.get("format"):
                # Generate a formatted string based on the format type
                format_type = prop_spec.get("format")
                if prop_name not in args:
                    if format_type == "email":
                        domains = ["example.com", "test.org", "mail.net", "domain.io"]
                        username = "".join(random.choices(string.ascii_lowercase, k=8))
                        domain = random.choice(domains)
                        args[prop_name] = f"{username}@{domain}"
                    elif format_type == "uri":
                        schemes = ["http", "https"]
                        domains = ["example.com", "test.org", "api.domain.io"]
                        paths = ["", "/api", "/v1/resources", "/users/123"]
                        scheme = random.choice(schemes)
                        domain = random.choice(domains)
                        path = random.choice(paths)
                        args[prop_name] = f"{scheme}://{domain}{path}"
                    elif format_type == "date-time":
                        args[prop_name] = (
                            datetime.now(timezone.utc)
                            .isoformat(timespec="seconds")
                            .replace("+00:00", "Z")
                        )
                    elif format_type == "uuid":
                        args[prop_name] = str(uuid.uuid4())
                    else:
                        args[prop_name] = await generate_realistic_text()
            # In realistic mode, only generate required properties and some
            # optional ones
            # But only if the property has a simple string schema without enum/format
            # constraints
            elif (prop_name not in args and
                  (prop_name in required or random.random() < 0.3)):
                # Only use fallback generation for simple string properties without
                # constraints
                if (prop_spec.get("type") == "string" and
                    not prop_spec.get("enum") and
                    not prop_spec.get("format") and
                    not prop_spec.get("pattern")):
                    args[prop_name] = await generate_realistic_text()
                # For properties with schemas, let the schema parser handle them
                elif prop_spec.get("type") in ["integer", "number", "boolean",
                                               "array", "object"]:
                    # These should have been handled by the schema parser above
                    pass
                else:
                    # Fallback for unknown types
                    args[prop_name] = await generate_realistic_text()

    return args
