#!/usr/bin/env python3
"""
Realistic Tool Strategy

This module provides strategies for generating realistic tool arguments and data.
Used in the realistic phase to test server behavior with valid, expected inputs.
"""

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
    min_year: int = 2020, max_year: int = 2030, include_microseconds: bool = True
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


def generate_realistic_text(min_size: int = 1, max_size: int = 100) -> str:
    """Generate realistic text using custom strategies."""
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
        chars = string.ascii_letters + string.digits + " ._-"
        length = random.randint(min_size, max_size)
        return "".join(random.choice(chars) for _ in range(length))
    elif strategy == "base64":
        return base64_strings(
            min_size=max(1, min_size // 2), max_size=max_size // 2
        ).example()
    elif strategy == "uuid":
        return uuid_strings().example()
    elif strategy == "timestamp":
        return timestamp_strings().example()
    elif strategy == "numbers":
        return str(random.randint(1, 999999))
    elif strategy == "mixed_alphanumeric":
        length = random.randint(min_size, max_size)
        chars = string.ascii_letters + string.digits
        return "".join(random.choice(chars) for _ in range(length))
    else:
        return "realistic_value"


def fuzz_tool_arguments_realistic(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Generate realistic tool arguments based on schema."""
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    args = {}

    for prop_name, prop_spec in properties.items():
        prop_type = prop_spec.get("type", "string")

        # Generate realistic values based on type
        if prop_type == "string":
            if "format" in prop_spec:
                fmt = prop_spec["format"]
                if fmt == "uuid":
                    args[prop_name] = str(uuid.uuid4())
                elif fmt == "date-time":
                    args[prop_name] = datetime.now(timezone.utc).isoformat()
                elif fmt == "email":
                    args[prop_name] = "user@example.com"
                elif fmt == "uri":
                    args[prop_name] = "https://example.com/api"
                else:
                    args[prop_name] = generate_realistic_text()
            else:
                args[prop_name] = generate_realistic_text()

        elif prop_type == "integer":
            min_val = prop_spec.get("minimum", 1)
            max_val = prop_spec.get("maximum", 1000)
            args[prop_name] = random.randint(min_val, max_val)

        elif prop_type == "number":
            min_val = prop_spec.get("minimum", 0.0)
            max_val = prop_spec.get("maximum", 1000.0)
            args[prop_name] = random.uniform(min_val, max_val)

        elif prop_type == "boolean":
            args[prop_name] = random.choice([True, False])

        elif prop_type == "array":
            items_spec = prop_spec.get("items", {})
            items_type = items_spec.get("type", "string")

            # Generate 1-3 realistic array items
            array_size = random.randint(1, 3)
            if items_type == "string":
                args[prop_name] = [generate_realistic_text() for _ in range(array_size)]
            elif items_type == "integer":
                args[prop_name] = [random.randint(1, 100) for _ in range(array_size)]
            elif items_type == "number":
                args[prop_name] = [
                    random.uniform(0.0, 100.0) for _ in range(array_size)
                ]
            else:
                args[prop_name] = ["item_" + str(i) for i in range(array_size)]

        elif prop_type == "object":
            # Generate a simple realistic object
            args[prop_name] = {
                "name": generate_realistic_text(),
                "value": random.randint(1, 100),
                "enabled": True,
            }
        else:
            # Fallback for unknown types
            args[prop_name] = generate_realistic_text()

    # Ensure required fields are present
    for required_field in required:
        if required_field not in args:
            args[required_field] = generate_realistic_text()

    return args
