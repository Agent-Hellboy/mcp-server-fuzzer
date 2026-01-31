#!/usr/bin/env python3
"""
Aggressive Tool Strategy

This module provides strategies for generating malicious, malformed, and edge-case
tool arguments. Used in the aggressive phase to test server security and robustness
with attack vectors.

Key principles:
- Constraint-aware payloads (fit within schema limits when possible)
- Attack payloads: SQL injection, XSS, path traversal, command injection
- Unicode tricks and encoding bypass
- Off-by-one violations for boundary testing
- No random garbage (e.g., "A" * 10000) - use targeted attacks instead
"""

import random
import string
from typing import Any

from ..schema_helpers import apply_schema_edge_cases
from ..interesting_values import (
    COMMAND_INJECTION,
    ENCODING_BYPASS,
    NOSQL_INJECTION,
    OVERFLOW_INTS,
    PATH_TRAVERSAL,
    SQL_INJECTION,
    SSRF_PAYLOADS,
    TYPE_CONFUSION,
    XSS_PAYLOADS,
    get_off_by_one_int,
    get_payload_within_length,
    inject_unicode_trick,
)

SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
UNICODE_CHARS = "漢字éñüřαβγδεζηθικλμνξοπρστυφχψω"
NULL_BYTES = ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05"]
ESCAPE_CHARS = ["\\", "\\'", '\\"', "\\n", "\\r", "\\t", "\\b", "\\f"]
HTML_ENTITIES = ["&lt;", "&gt;", "&amp;", "&quot;", "&#x27;", "&#x2F;"]
MIN_TOKENS = ("min", "lower", "start")
MAX_TOKENS = ("max", "upper", "limit", "size", "count", "timeout")


def generate_aggressive_text(
    min_size: int = 1,
    max_size: int = 100,
    key: str | None = None,
    *,
    allow_overflow: bool = True,
) -> str:
    """
    Generate aggressive text for security/robustness testing.

    This function generates constraint-aware attack payloads that fit within
    the specified length limits. It prioritizes actual attack vectors over
    random garbage.
    """
    def _normalize_sizes(
        raw_min: Any,
        raw_max: Any,
        default_min: int = 1,
        default_max: int = 100,
    ) -> tuple[int, int]:
        try:
            min_value = default_min if raw_min is None else int(raw_min)
        except (TypeError, ValueError):
            min_value = default_min
        try:
            max_value = default_max if raw_max is None else int(raw_max)
        except (TypeError, ValueError):
            max_value = default_max
        min_value = max(0, min_value)
        max_value = max(0, max_value)
        if min_value > max_value:
            min_value, max_value = max_value, min_value
        return min_value, max_value

    min_size, max_size = _normalize_sizes(min_size, max_size)

    # Choose strategy weighted toward attack payloads
    strategies = [
        "sql_injection",
        "sql_injection",
        "xss",
        "xss",
        "path_traversal",
        "nosql_injection",
        "command_injection",
        "ssrf",
        "broken_base64",
        "broken_timestamp",
        "unicode",
        "null_bytes",
        "escape_chars",
        "html_entities",
        "overflow",
        "mixed",
        "extreme",
        "unicode_trick",
        "encoding_bypass",
        "type_confusion",
        "broken_uuid",
        "special_chars",
        "broken_format",
        "edge_chars",
    ]
    strategy = random.choice(strategies)

    def _fit_to_length(value: str) -> str:
        """Fit value to length constraints."""
        if len(value) < min_size:
            value = value + "a" * (min_size - len(value))
        if len(value) > max_size:
            value = value[:max_size]
        return value

    # Use semantic hints from key name
    if key:
        lowered = key.lower()
        if any(x in lowered for x in ("uri", "url", "href", "link")):
            return _fit_to_length(random.choice(SSRF_PAYLOADS))
        if any(x in lowered for x in ("path", "file", "dir", "folder")):
            return _fit_to_length(random.choice(PATH_TRAVERSAL))
        if any(x in lowered for x in ("query", "search", "sql", "filter")):
            return _fit_to_length(get_payload_within_length(max_size, "sql"))
        if any(x in lowered for x in ("mongo", "nosql")):
            return _fit_to_length(random.choice(NOSQL_INJECTION))
        if any(x in lowered for x in ("html", "content", "body", "text")):
            return _fit_to_length(get_payload_within_length(max_size, "xss"))
        if any(x in lowered for x in ("cmd", "command", "exec", "shell")):
            return _fit_to_length(random.choice(COMMAND_INJECTION))

    if strategy == "sql_injection":
        return _fit_to_length(random.choice(SQL_INJECTION))
    elif strategy == "nosql_injection":
        return _fit_to_length(random.choice(NOSQL_INJECTION))
    elif strategy == "xss":
        return _fit_to_length(random.choice(XSS_PAYLOADS))
    elif strategy == "path_traversal":
        return _fit_to_length(random.choice(PATH_TRAVERSAL))
    elif strategy == "command_injection":
        return _fit_to_length(random.choice(COMMAND_INJECTION))
    elif strategy == "ssrf":
        return _fit_to_length(random.choice(SSRF_PAYLOADS))
    elif strategy == "broken_base64":
        broken_base64 = [
            "InvalidBase64!@#$",
            "Base64!@#$",
        ]
        return _fit_to_length(random.choice(broken_base64))
    elif strategy == "broken_timestamp":
        broken_timestamps = [
            "not-a-timestamp",
            "2024-13-40T25:70:99Z",
        ]
        return _fit_to_length(random.choice(broken_timestamps))
    elif strategy == "unicode":
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(UNICODE_CHARS) for _ in range(length))
        )
    elif strategy == "null_bytes":
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(NULL_BYTES) for _ in range(length))
        )
    elif strategy == "escape_chars":
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(ESCAPE_CHARS) for _ in range(length))
        )
    elif strategy == "html_entities":
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(HTML_ENTITIES) for _ in range(length))
        )
    elif strategy == "overflow":
        overflow_values = [
            "A" * 1000,
            "B" * 2000,
        ]
        if allow_overflow:
            return random.choice(overflow_values)
        # Respect max_size unless overflow is explicitly allowed.
        return _fit_to_length(random.choice(overflow_values))
    elif strategy == "mixed":
        length = random.randint(min_size, max_size)
        alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS
        return _fit_to_length(
            "".join(random.choice(alphabet) for _ in range(length))
        )
    elif strategy == "extreme":
        extreme_values = [
            "",
            " " * max_size,
            "A" * max(1, max_size * 10),
        ]
        return random.choice(extreme_values)
    elif strategy == "unicode_trick":
        # Embed unicode trick in normal-looking value
        base = "test_value"
        return _fit_to_length(inject_unicode_trick(base, max_size))
    elif strategy == "encoding_bypass":
        return _fit_to_length(random.choice(ENCODING_BYPASS))
    elif strategy == "type_confusion":
        return _fit_to_length(random.choice(TYPE_CONFUSION))
    elif strategy == "broken_uuid":
        broken_uuids = [
            "not-a-uuid-at-all",
            "1234",
            "zzzz-zzzz-zzzz-zzzz",
        ]
        return _fit_to_length(random.choice(broken_uuids))
    elif strategy == "special_chars":
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(SPECIAL_CHARS) for _ in range(length))
        )
    elif strategy == "broken_format":
        # Invalid formats that might bypass validation
        broken_formats = [
            "not-a-uuid-at-all",
            "2024-13-40T25:70:99Z",
            "invalid@",
            "http://[invalid",
            "Base64!@#$",
        ]
        return _fit_to_length(random.choice(broken_formats))
    elif strategy == "edge_chars":
        # Special characters that might cause parsing issues
        edge_values = [
            "'" + "a" * max(0, max_size - 2) + "'",
            '"' + "a" * max(0, max_size - 2) + '"',
            "\\" * min(max_size, 10),
            "\n\r\t" * (max_size // 3),
        ]
        return _fit_to_length(random.choice(edge_values))
    else:
        length = random.randint(min_size, max_size)
        return "".join(random.choice(string.ascii_letters) for _ in range(length))


def _generate_aggressive_integer(
    min_value: int | None = None,
    max_value: int | None = None,
    schema: dict[str, Any] | None = None,
) -> int:
    """
    Generate aggressive integer with off-by-one violations and edge cases.

    Prioritizes:
    1. Off-by-one violations (max+1, min-1) when constraints exist
    2. Integer overflow values
    3. Boundary values within range
    """
    # Extract constraints from schema if provided
    if schema:
        min_value = schema.get("minimum", min_value)
        max_value = schema.get("maximum", max_value)

    # Use defaults if still None
    if min_value is None:
        min_value = -1000
    if max_value is None:
        max_value = 1000
    if min_value > max_value:
        min_value, max_value = max_value, min_value

    strategies = [
        "off_by_one",
        "boundary",
        "overflow",
        "normal",
        "extreme",
        "zero",
        "negative",
        "special",
    ]
    strategy = random.choice(strategies)

    if strategy == "off_by_one":
        # Off-by-one violations to test boundary validation
        if schema and schema.get("maximum") is not None:
            return int(schema["maximum"]) + 1
        if schema and schema.get("minimum") is not None:
            return int(schema["minimum"]) - 1
        # Fallback to overflow
        return get_off_by_one_int(max_value, min_value)

    elif strategy == "overflow":
        overflow_candidates = [
            value
            for value in OVERFLOW_INTS
            if value < min_value or value > max_value
        ]
        return random.choice(overflow_candidates or OVERFLOW_INTS)

    elif strategy == "boundary":
        # Boundary values that ARE within range (edge testing)
        boundary_values = [
            min_value,
            max_value,
            min_value + 1,
            max_value - 1,
            0, -1, 1,
            127, 128, 255, 256,
            32767, 32768, 65535, 65536,
        ]
        valid = [v for v in boundary_values if min_value <= v <= max_value]
        if valid:
            return random.choice(valid)
        return random.randint(min_value, max_value)

    elif strategy == "extreme":
        extreme_values = [
            -2147483648,
            2147483647,
            -9223372036854775808,
            9223372036854775807,
            0,
            -1,
            1,
        ]
        return random.choice(extreme_values)
    elif strategy == "zero":
        return 0
    elif strategy == "negative":
        upper = min(-1, max_value)
        if upper < min_value:
            return min_value - 1
        return random.randint(min_value, upper)
    elif strategy == "special":
        special_values = [42, 69, 420, 1337, 8080, 65535]
        return random.choice(special_values)
    else:
        # Normal value within range
        return random.randint(min_value, max_value)


def _generate_aggressive_float(
    min_value: float | None = None,
    max_value: float | None = None,
    schema: dict[str, Any] | None = None,
) -> float:
    """
    Generate aggressive float with edge cases and special values.

    Prioritizes:
    1. Off-by-one violations when constraints exist
    2. Special float values (inf, -inf, tiny, huge)
    3. Boundary values
    """
    from ..interesting_values import SPECIAL_FLOATS

    # Extract constraints from schema if provided
    if schema:
        min_value = schema.get("minimum", min_value)
        max_value = schema.get("maximum", max_value)

    # Use defaults if still None
    if min_value is None:
        min_value = -1000.0
    if max_value is None:
        max_value = 1000.0
    if min_value > max_value:
        min_value, max_value = max_value, min_value

    strategies = [
        "off_by_one",
        "infinity",
        "special",
        "boundary",
        "normal",
        "extreme",
        "zero",
        "negative",
        "tiny",
        "huge",
    ]
    strategy = random.choice(strategies)

    if strategy == "off_by_one":
        # Off-by-one violations
        if schema and schema.get("maximum") is not None:
            return float(schema["maximum"]) + 0.001
        if schema and schema.get("minimum") is not None:
            return float(schema["minimum"]) - 0.001
        return max_value + 0.001

    elif strategy == "infinity":
        return random.choice([float("inf"), float("-inf")])

    elif strategy == "special":
        return random.choice(SPECIAL_FLOATS)

    elif strategy == "boundary":
        # Boundary values within range
        boundaries = [min_value, max_value, 0.0, -0.0, 1.0, -1.0]
        valid = [v for v in boundaries if min_value <= v <= max_value]
        if valid:
            return random.choice(valid)
        return random.uniform(min_value, max_value)

    elif strategy == "extreme":
        extreme_values = [0.0, -0.0, 1.0, -1.0, 3.14159, -3.14159]
        return random.choice(extreme_values)
    elif strategy == "zero":
        return 0.0
    elif strategy == "negative":
        upper = min(-1.0, max_value)
        if upper < min_value:
            return min_value - 1.0
        return random.uniform(min_value, upper)
    elif strategy == "tiny":
        return random.uniform(1e-10, 1e-5)
    elif strategy == "huge":
        return random.uniform(1e10, 1e15)
    else:
        return random.uniform(min_value, max_value)


def _clamp_string(value: str, min_length: int | None, max_length: int | None) -> str:
    """Fit string to length constraints."""
    min_len = min_length or 0
    if max_length is not None and len(value) > max_length:
        value = value[:max_length]
    if len(value) < min_len:
        value = value + "a" * (min_len - len(value))
    return value


def _pick_semantic_string(name: str, max_length: int | None = None) -> str:
    """
    Pick a semantic attack payload based on field name.

    Uses constraint-aware payloads that fit within max_length.
    """
    max_len = max_length if max_length is not None else 100

    lowered = name.lower()

    if any(token in lowered for token in ("uri", "url", "href")):
        payload = random.choice(SSRF_PAYLOADS)
        return _clamp_string(payload, 0, max_len)

    if any(token in lowered for token in ("path", "file", "dir", "folder")):
        payload = get_payload_within_length(max_len, "path")
        return _clamp_string(payload, 0, max_len)

    if any(token in lowered for token in ("query", "search", "filter", "sql")):
        payload = get_payload_within_length(max_len, "sql")
        return _clamp_string(payload, 0, max_len)

    if any(token in lowered for token in ("html", "content", "body", "text")):
        payload = get_payload_within_length(max_len, "xss")
        return _clamp_string(payload, 0, max_len)

    if any(token in lowered for token in ("cmd", "command", "exec", "shell")):
        payload = random.choice(COMMAND_INJECTION)
        return _clamp_string(payload, 0, max_len)

    if any(token in lowered for token in ("id", "name", "key", "cursor")):
        # Use unicode trick or type confusion instead of garbage
        base = "test_id"
        payload = inject_unicode_trick(base, max_len)
        return _clamp_string(payload, 0, max_len)

    # Default: SQL injection payload (most common vulnerability)
    payload = get_payload_within_length(max_len, "sql")
    return _clamp_string(payload, 0, max_len)


def _pick_semantic_number(name: str, spec: dict[str, Any]) -> int | float:
    """
    Pick a semantic numeric value based on field name.

    Prioritizes off-by-one violations when constraints exist.
    """
    lowered = name.lower()
    minimum = spec.get("minimum")
    maximum = spec.get("maximum")

    # For "min" fields, try to go below minimum
    if any(token in lowered for token in MIN_TOKENS):
        if minimum is not None:
            return minimum - 1  # Off-by-one below
        return -1

    # For "max" fields, try to exceed maximum
    if any(token in lowered for token in MAX_TOKENS):
        if maximum is not None:
            return maximum + 1  # Off-by-one above
        return 2147483648  # INT32_MAX + 1

    # Default: try off-by-one on maximum
    if maximum is not None:
        return maximum + 1
    if minimum is not None:
        return minimum - 1

    # Fallback to reasonable overflow value
    return 2147483648


def _apply_semantic_edge_cases(args: dict[str, Any], schema: dict[str, Any]) -> None:
    """
    Apply semantic attack payloads based on field names and constraints.

    This function mutates args in-place with constraint-aware attack payloads.
    """
    properties = schema.get("properties", {})
    for key, value in list(args.items()):
        spec = properties.get(key)
        if not isinstance(spec, dict):
            continue

        # Skip const values (must not be changed)
        if "const" in spec:
            continue

        # For enums, sometimes try an invalid value
        if "enum" in spec:
            enum_values = spec["enum"]
            if random.random() < 0.3 and enum_values:
                # Try case variation or invalid value
                last = enum_values[-1]
                if isinstance(last, str):
                    args[key] = last.upper() if last.islower() else last.lower()
                continue
            continue

        prop_type = spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else None

        if prop_type == "string" and isinstance(value, str):
            max_length = spec.get("maxLength")
            min_length = spec.get("minLength")

            # Handle format-specific attacks
            format_type = spec.get("format")
            if format_type == "email":
                # Email injection attempts
                candidate = "fuzzer+' OR '1'='1@example.com"
            elif format_type == "uuid":
                # Invalid but plausible UUID
                candidate = "00000000-0000-0000-0000-000000000000"
            elif format_type == "uri":
                candidate = random.choice(SSRF_PAYLOADS)
            else:
                # Use semantic string picker with length constraint
                candidate = _pick_semantic_string(key, max_length)

            args[key] = _clamp_string(candidate, min_length, max_length)

        elif prop_type in ("integer", "number") and isinstance(value, (int, float)):
            args[key] = _pick_semantic_number(key, spec)


def fuzz_tool_arguments_aggressive(tool: dict[str, Any]) -> dict[str, Any]:
    """
    Generate aggressive/malicious tool arguments.

    This function generates constraint-aware attack payloads:
    - SQL injection, XSS, path traversal, command injection
    - Unicode tricks and encoding bypass
    - Off-by-one boundary violations
    - Type confusion attempts
    """
    from ..schema_parser import make_fuzz_strategy_from_jsonschema

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        schema = {}

    # Use the enhanced schema parser to generate aggressive values
    try:
        parsed_args = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
    except Exception:
        parsed_args = {}

    # If the schema parser returned something other than a dict, create a default dict
    if not isinstance(parsed_args, dict):
        parsed_args = {}

    args = parsed_args
    used_fallback = not parsed_args

    # Generate constraint-aware fallback values
    def _fallback_value(prop_spec: Any, prop_name: str | None = None) -> Any:
        if not isinstance(prop_spec, dict):
            return generate_aggressive_text(key=prop_name)

        prop_type = prop_spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else "string"

        if prop_type == "integer":
            return _generate_aggressive_integer(schema=prop_spec)
        if prop_type == "number":
            return _generate_aggressive_float(schema=prop_spec)
        if prop_type == "boolean":
            return random.choice([True, False])
        if prop_type == "array":
            # Generate array with attack payloads
            min_items = prop_spec.get("minItems", 0)
            max_items = prop_spec.get("maxItems", 3)
            try:
                min_items = int(min_items)
            except (TypeError, ValueError):
                min_items = 0
            try:
                max_items = int(max_items)
            except (TypeError, ValueError):
                max_items = 3
            min_items = max(0, min_items)
            max_items = max(0, max_items)
            if min_items > max_items:
                min_items, max_items = max_items, min_items
            capped_max = min(max_items, 5)
            if capped_max < min_items:
                capped_max = min_items
            count = random.randint(min_items, capped_max)
            items_schema = prop_spec.get("items", {"type": "string"})
            return [_fallback_value(items_schema) for _ in range(count)]
        if prop_type == "object":
            return {}

        # String type - use constraint-aware payload
        max_length = prop_spec.get("maxLength", 100)
        min_length = prop_spec.get("minLength", 0)
        return generate_aggressive_text(
            min_size=min_length,
            max_size=max_length,
            key=prop_name,
        )

    if not args and schema.get("properties"):
        # Fallback to basic property handling
        properties = schema.get("properties", {})

        for prop_name, prop_spec in properties.items():
            if random.random() < 0.8:  # 80% chance to include each property
                args[prop_name] = _fallback_value(prop_spec, prop_name)

    # Ensure required keys exist (values may still be adversarial)
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    for key in required or []:
        if key not in args:
            prop_spec = properties.get(key)
            args[key] = _fallback_value(prop_spec, key)

    if not used_fallback:
        _apply_semantic_edge_cases(args, schema)

    if schema:
        args = apply_schema_edge_cases(
            args, schema, phase="aggressive", key=tool.get("name")
        )

    return args
