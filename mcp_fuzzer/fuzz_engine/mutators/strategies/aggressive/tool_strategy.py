#!/usr/bin/env python3
"""
Aggressive Tool Strategy

This module provides strategies for generating malicious, malformed, and edge-case
tool arguments. Used in the aggressive phase to test server security and robustness
with attack vectors.
"""

import random
import string
from typing import Any

from ..schema_helpers import apply_schema_edge_cases

# Attack payloads and malicious data
SQL_INJECTION = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT * FROM users --",
    "'; DELETE FROM table WHERE 1=1; --",
    "admin'--",
    "admin'/*",
    "' OR 1=1#",
    "' OR 'x'='x",
    "'; EXEC xp_cmdshell('dir'); --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "<svg/onload=alert('xss')>",
    "<iframe src=javascript:alert('xss')>",
    "<body onload=alert('xss')>",
    "'><script>alert('xss')</script>",
    "\"><script>alert('xss')</script>",
    "<script>document.cookie</script>",
    "<script>window.location='http://evil.com'</script>",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "file:///etc/passwd",
    "file:///c:/windows/system32/config/sam",
    "\\..\\..\\..\\..\\..\\..\\..\\..\\..",
]

OVERFLOW_VALUES = [
    "A" * 1000,
    "A" * 10000,
    "A" * 100000,
    "\x00" * 1000,
    "0" * 1000,
    "9" * 1000,
    " " * 1000,
    "\n" * 1000,
    "\t" * 1000,
    "漢" * 1000,  # Unicode
]

SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
UNICODE_CHARS = "漢字éñüřαβγδεζηθικλμνξοπρστυφχψω"
NULL_BYTES = ["\x00", "\x01", "\x02", "\x03", "\x04", "\x05"]
ESCAPE_CHARS = ["\\", "\\'", '\\"', "\\n", "\\r", "\\t", "\\b", "\\f"]
HTML_ENTITIES = ["&lt;", "&gt;", "&amp;", "&quot;", "&#x27;", "&#x2F;"]


def generate_aggressive_text(min_size: int = 1, max_size: int = 100) -> str:
    """Generate aggressive text for security/robustness testing."""
    strategy = random.choice(
        [
            "broken_base64",
            "broken_uuid",
            "broken_timestamp",
            "sql_injection",
            "xss",
            "path_traversal",
            "overflow",
            "special_chars",
            "unicode",
            "null_bytes",
            "escape_chars",
            "html_entities",
            "mixed",
            "extreme",
        ]
    )

    length = random.randint(min_size, max_size)

    if strategy == "broken_base64":
        # Invalid base64 strings
        return random.choice(
            [
                "InvalidBase64!@#$",
                "Base64===WithTooManyEquals",
                "Base64WithInvalidChars!@#",
                "VGhpcyBpcyBub3QgdmFsaWQgYmFzZTY0!",
            ]
        )
    elif strategy == "broken_uuid":
        # Invalid UUID formats
        return random.choice(
            [
                "not-a-uuid-at-all",
                "12345678-1234-1234-1234-123456789012345",  # Too long
                "1234-5678-1234-1234-123456789012",  # Wrong format
                "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # Invalid chars
                "{12345678-1234-1234-1234-123456789012}",  # With braces
            ]
        )
    elif strategy == "broken_timestamp":
        # Invalid timestamp formats
        return random.choice(
            [
                "not-a-timestamp",
                "2024-13-40T25:70:99Z",  # Invalid date/time
                "2024/01/01 12:00:00",  # Wrong format
                f"{random.randint(61, 99)}.INVALID+BROKEN:00",
            ]
        )
    elif strategy == "special_chars":
        return "".join(random.choice(SPECIAL_CHARS) for _ in range(length))
    elif strategy == "unicode":
        return "".join(random.choice(UNICODE_CHARS) for _ in range(length))
    elif strategy == "null_bytes":
        return "".join(random.choice(NULL_BYTES) for _ in range(length))
    elif strategy == "escape_chars":
        return "".join(random.choice(ESCAPE_CHARS) for _ in range(length))
    elif strategy == "html_entities":
        return "".join(random.choice(HTML_ENTITIES) for _ in range(length))
    elif strategy == "sql_injection":
        return random.choice(SQL_INJECTION)
    elif strategy == "xss":
        return random.choice(XSS_PAYLOADS)
    elif strategy == "path_traversal":
        return random.choice(PATH_TRAVERSAL)
    elif strategy == "overflow":
        return random.choice(OVERFLOW_VALUES)
    elif strategy == "mixed":
        chars = string.printable + UNICODE_CHARS + SPECIAL_CHARS
        return "".join(random.choice(chars) for _ in range(length))
    elif strategy == "extreme":
        extreme_values = [
            "",  # Empty string
            " " * length,  # Spaces only
            "\t" * length,  # Tabs only
            "\n" * length,  # Newlines only
            "0" * length,  # Zeros only
            "A" * length,  # A's only
            ("100" * ((length + 2) // 3))[:length],  # digits only; enforce exact length
            "!@#" * (length // 3),  # Special chars only
        ]
        return random.choice(extreme_values)
    else:
        return "".join(random.choice(string.printable) for _ in range(length))


def _generate_aggressive_integer(
    min_value: int = -1000000, max_value: int = 1000000
) -> int:
    """Generate aggressive random integer with extreme values and edge cases."""
    strategy = random.choice(
        [
            "normal",
            "extreme",
            "zero",
            "negative",
            "overflow",
            "special",
            "boundary",
        ]
    )

    if strategy == "normal":
        return random.randint(min_value, max_value)
    elif strategy == "extreme":
        # Extreme values that might cause overflow or underflow
        extremes = [
            -2147483648,  # INT32_MIN
            2147483647,  # INT32_MAX
            -9223372036854775808,  # INT64_MIN
            9223372036854775807,  # INT64_MAX
            0,
            -1,
            1,
        ]
        return random.choice(extremes)
    elif strategy == "zero":
        return 0
    elif strategy == "negative":
        return random.randint(-1000000, -1)
    elif strategy == "overflow":
        # Values designed to cause buffer overflows
        return random.choice([999999999, -999999999, 2**31, -(2**31)])
    elif strategy == "special":
        # Special mathematical values (converted to int)
        return random.choice([42, 69, 420, 1337, 8080, 65535])
    elif strategy == "boundary":
        # Boundary values around common limits
        return random.choice([-1, 0, 1, 255, 256, 65535, 65536])
    else:
        return random.randint(min_value, max_value)


def _generate_aggressive_float() -> float:
    """Generate aggressive random float with extreme values and edge cases."""
    strategy = random.choice(
        ["normal", "extreme", "zero", "negative", "tiny", "huge", "infinity"]
    )

    if strategy == "normal":
        return random.uniform(-1000.0, 1000.0)
    elif strategy == "extreme":
        extremes = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            3.14159,
            -3.14159,
        ]
        return random.choice(extremes)
    elif strategy == "zero":
        return 0.0
    elif strategy == "negative":
        return random.uniform(-1000.0, -0.001)
    elif strategy == "tiny":
        return random.uniform(1e-10, 1e-5)
    elif strategy == "huge":
        return random.uniform(1e10, 1e15)
    elif strategy == "infinity":
        return random.choice([float("inf"), float("-inf")])
    else:
        return random.uniform(-1000.0, 1000.0)


def _clamp_string(value: str, min_length: int | None, max_length: int | None) -> str:
    min_len = min_length or 0
    if max_length is not None and len(value) > max_length:
        value = value[:max_length]
    if len(value) < min_len:
        value = value + ("A" * (min_len - len(value)))
    return value


def _pick_semantic_string(name: str) -> str:
    lowered = name.lower()
    if any(token in lowered for token in ("uri", "url", "href")):
        return "file:///tmp/mcp-fuzzer/../../etc/passwd"
    if any(token in lowered for token in ("path", "file", "dir", "folder")):
        return "/tmp/mcp-fuzzer/../../etc/passwd"
    if "cursor" in lowered:
        return "cursor_" + ("A" * 256)
    if any(token in lowered for token in ("id", "name", "key")):
        return "id_" + ("A" * 128)
    if any(token in lowered for token in ("query", "search", "filter")):
        return "q=" + ("A" * 512)
    return "A" * 256


def _pick_semantic_number(name: str, spec: dict[str, Any]) -> int | float:
    lowered = name.lower()
    minimum = spec.get("minimum")
    maximum = spec.get("maximum")
    if (
        any(token in lowered for token in ("min", "lower", "start"))
        and minimum is not None
    ):
        return minimum
    if (
        any(
            token in lowered
            for token in ("max", "upper", "limit", "size", "count", "timeout")
        )
        and maximum is not None
    ):
        return maximum
    return maximum if maximum is not None else (
        minimum if minimum is not None else 2**31 - 1
    )


def _apply_semantic_edge_cases(args: dict[str, Any], schema: dict[str, Any]) -> None:
    properties = schema.get("properties", {})
    for key, value in list(args.items()):
        spec = properties.get(key)
        if not isinstance(spec, dict):
            continue

        if "enum" in spec or "const" in spec or "pattern" in spec:
            continue

        prop_type = spec.get("type")
        if isinstance(prop_type, list):
            prop_type = prop_type[0] if prop_type else None

        if prop_type == "string" and isinstance(value, str):
            candidate = _pick_semantic_string(key)
            if spec.get("format") == "email":
                candidate = "fuzzer+" + ("a" * 24) + "@example.com"
            elif spec.get("format") == "uuid":
                candidate = "00000000-0000-0000-0000-000000000000"
            min_length = spec.get("minLength")
            max_length = spec.get("maxLength")
            args[key] = _clamp_string(candidate, min_length, max_length)
        elif prop_type in ("integer", "number") and isinstance(value, (int, float)):
            args[key] = _pick_semantic_number(key, spec)


def fuzz_tool_arguments_aggressive(tool: dict[str, Any]) -> dict[str, Any]:
    """Generate aggressive/malicious tool arguments."""
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

    # Ensure we have at least some arguments
    def _fallback_value(prop_spec: Any) -> Any:
        if not isinstance(prop_spec, dict):
            return generate_aggressive_text()
        prop_type = prop_spec.get("type")
        if prop_type == "integer":
            min_v = prop_spec.get("minimum", -1000000)
            max_v = prop_spec.get("maximum", 1000000)
            return _generate_aggressive_integer(min_v, max_v)
        if prop_type == "number":
            return _generate_aggressive_float()
        if prop_type == "boolean":
            return random.choice([True, False])
        if prop_type == "array":
            return []
        if prop_type == "object":
            return {}
        return generate_aggressive_text()

    if not args and schema.get("properties"):
        # Fallback to basic property handling
        properties = schema.get("properties", {})

        for prop_name, prop_spec in properties.items():
            if random.random() < 0.8:  # 80% chance to include each property
                args[prop_name] = _fallback_value(prop_spec)

    # Ensure required keys exist (values may still be adversarial)
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    for key in required or []:
        if key not in args:
            prop_spec = properties.get(key)
            args[key] = _fallback_value(prop_spec)

    if not used_fallback:
        _apply_semantic_edge_cases(args, schema)

    if schema:
        args = apply_schema_edge_cases(
            args, schema, phase="aggressive", key=tool.get("name")
        )

    return args
