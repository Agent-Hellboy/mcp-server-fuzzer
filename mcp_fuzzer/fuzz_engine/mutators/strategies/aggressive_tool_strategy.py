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

from ..rng_context import lazy_rng as random
import string
from typing import Any

from .schema_helpers import apply_schema_edge_cases
from .interesting_values import (
    COMMAND_INJECTION,
    ENCODING_BYPASS,
    NOSQL_INJECTION,
    OVERFLOW_INTS,
    PATH_TRAVERSAL,
    SPECIAL_FLOATS,
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

_MIXED_ALPHABET = string.ascii_letters + string.digits + SPECIAL_CHARS
_BROKEN_BASE64 = ["InvalidBase64!@#$", "Base64!@#$"]
_BROKEN_TIMESTAMPS = ["not-a-timestamp", "2024-13-40T25:70:99Z"]
_BROKEN_UUIDS = ["not-a-uuid-at-all", "1234", "zzzz-zzzz-zzzz-zzzz"]
_BROKEN_FORMATS = [
    "not-a-uuid-at-all",
    "2024-13-40T25:70:99Z",
    "invalid@",
    "http://[invalid",
    "Base64!@#$",
]
_OVERFLOW_STRINGS = ["A" * 1000, "B" * 2000]

# Field-name hints -> payload picker, evaluated in order. Matched by substring
# against the lowercased key; the picker receives the max length budget.
_TEXT_KEY_HINTS: list[tuple[tuple[str, ...], Any]] = [
    (("uri", "url", "href", "link"), lambda _n: random.choice(SSRF_PAYLOADS)),
    (("path", "file", "dir", "folder"), lambda _n: random.choice(PATH_TRAVERSAL)),
    (("query", "search", "sql", "filter"),
     lambda n: get_payload_within_length(n, "sql")),
    (("mongo", "nosql"), lambda _n: random.choice(NOSQL_INJECTION)),
    (("html", "content", "body", "text"),
     lambda n: get_payload_within_length(n, "xss")),
    (("cmd", "command", "exec", "shell"), lambda _n: random.choice(COMMAND_INJECTION)),
]

# Field-name hints for the schema-aware semantic pass (_pick_semantic_string).
# Deliberately NOT the same table as _TEXT_KEY_HINTS: this pass runs against a
# typed schema property, so it prefers length-aware pickers ("path" draws a
# payload that fits rather than any traversal string) and carries an extra
# identifier hint. Merging the two would change which payloads are emitted.
_SEMANTIC_KEY_HINTS: list[tuple[tuple[str, ...], Any]] = [
    (("uri", "url", "href"), lambda _n: random.choice(SSRF_PAYLOADS)),
    (("path", "file", "dir", "folder"),
     lambda n: get_payload_within_length(n, "path")),
    (("query", "search", "filter", "sql"),
     lambda n: get_payload_within_length(n, "sql")),
    (("html", "content", "body", "text"),
     lambda n: get_payload_within_length(n, "xss")),
    (("cmd", "command", "exec", "shell"), lambda _n: random.choice(COMMAND_INJECTION)),
    # Use a unicode trick on identifiers instead of garbage.
    (("id", "name", "key", "cursor"),
     lambda n: inject_unicode_trick("test_id", n)),
]

# Strategies that just pick from a fixed payload pool, no length awareness.
_POOL_STRATEGIES: dict[str, list[str]] = {
    "sql_injection": SQL_INJECTION,
    "nosql_injection": NOSQL_INJECTION,
    "xss": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL,
    "command_injection": COMMAND_INJECTION,
    "ssrf": SSRF_PAYLOADS,
    "broken_base64": _BROKEN_BASE64,
    "broken_timestamp": _BROKEN_TIMESTAMPS,
    "encoding_bypass": ENCODING_BYPASS,
    "type_confusion": TYPE_CONFUSION,
    "broken_uuid": _BROKEN_UUIDS,
    "broken_format": _BROKEN_FORMATS,
}

# Strategies that build a random-length string from a character pool.
_CHARSET_STRATEGIES: dict[str, str | list[str]] = {
    "unicode": UNICODE_CHARS,
    "null_bytes": NULL_BYTES,
    "escape_chars": ESCAPE_CHARS,
    "html_entities": HTML_ENTITIES,
    "mixed": _MIXED_ALPHABET,
    "special_chars": SPECIAL_CHARS,
}

# Choose strategy weighted toward attack payloads (duplicates raise the odds).
_TEXT_STRATEGIES = [
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

_INT_STRATEGIES = [
    "off_by_one",
    "boundary",
    "overflow",
    "normal",
    "extreme",
    "zero",
    "negative",
    "special",
]

# int32/int64 rails plus the values most likely to trip sign/zero handling.
_EXTREME_INTS = [
    -2147483648,
    2147483647,
    -9223372036854775808,
    9223372036854775807,
    0,
    -1,
    1,
]

_SPECIAL_INTS = [42, 69, 420, 1337, 8080, 65535]

_FLOAT_STRATEGIES = [
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

_INFINITIES = [float("inf"), float("-inf")]

_EXTREME_FLOATS = [0.0, -0.0, 1.0, -1.0, 3.14159, -3.14159]


def _normalize_sizes(
    raw_min: Any,
    raw_max: Any,
    default_min: int = 1,
    default_max: int = 100,
) -> tuple[int, int]:
    """Coerce a (min, max) size pair to a sane, ordered, non-negative range."""
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
    min_size, max_size = _normalize_sizes(min_size, max_size)

    strategy = random.choice(_TEXT_STRATEGIES)

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
        for tokens, pick in _TEXT_KEY_HINTS:
            if any(token in lowered for token in tokens):
                return _fit_to_length(pick(max_size))

    pool = _POOL_STRATEGIES.get(strategy)
    if pool is not None:
        return _fit_to_length(random.choice(pool))

    charset = _CHARSET_STRATEGIES.get(strategy)
    if charset is not None:
        length = random.randint(min_size, max_size)
        return _fit_to_length(
            "".join(random.choice(charset) for _ in range(length))
        )

    if strategy == "overflow":
        if allow_overflow:
            return random.choice(_OVERFLOW_STRINGS)
        # Respect max_size unless overflow is explicitly allowed.
        return _fit_to_length(random.choice(_OVERFLOW_STRINGS))
    elif strategy == "extreme":
        extreme_values = [
            "",
            " " * max_size,
            "A" * max(1, max_size * 10),
        ]
        return random.choice(extreme_values)
    elif strategy == "unicode_trick":
        # Embed unicode trick in normal-looking value
        return _fit_to_length(inject_unicode_trick("test_value", max_size))
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

    strategy = random.choice(_INT_STRATEGIES)

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
        return random.choice(_EXTREME_INTS)
    elif strategy == "zero":
        return 0
    elif strategy == "negative":
        upper = min(-1, max_value)
        if upper < min_value:
            return min_value - 1
        return random.randint(min_value, upper)
    elif strategy == "special":
        return random.choice(_SPECIAL_INTS)
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

    strategy = random.choice(_FLOAT_STRATEGIES)

    if strategy == "off_by_one":
        # Off-by-one violations
        if schema and schema.get("maximum") is not None:
            return float(schema["maximum"]) + 0.001
        if schema and schema.get("minimum") is not None:
            return float(schema["minimum"]) - 0.001
        return max_value + 0.001

    elif strategy == "infinity":
        return random.choice(_INFINITIES)

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
        return random.choice(_EXTREME_FLOATS)
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

    for tokens, pick in _SEMANTIC_KEY_HINTS:
        if any(token in lowered for token in tokens):
            return _clamp_string(pick(max_len), 0, max_len)

    # Default: SQL injection payload (most common vulnerability)
    return _clamp_string(get_payload_within_length(max_len, "sql"), 0, max_len)


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
    from .schema_parser import make_fuzz_strategy_from_jsonschema

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
