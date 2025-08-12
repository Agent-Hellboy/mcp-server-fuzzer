#!/usr/bin/env python3
"""
Aggressive Tool Strategy

This module provides strategies for generating malicious, malformed, and edge-case
tool arguments. Used in the aggressive phase to test server security and robustness
with attack vectors.
"""

import random
import string
from typing import Any, Dict

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
        ["normal", "extreme", "zero", "negative", "overflow", "special", "boundary"]
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
        ["normal", "extreme", "zero", "negative", "infinity", "tiny", "huge"]
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
    elif strategy == "infinity":
        return random.choice([float("inf"), float("-inf")])
    elif strategy == "tiny":
        return random.uniform(1e-10, 1e-5)
    elif strategy == "huge":
        return random.uniform(1e10, 1e15)
    else:
        return random.uniform(-1000.0, 1000.0)


def fuzz_tool_arguments_aggressive(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Generate aggressive/malicious tool arguments."""
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})

    args = {}

    for prop_name, prop_spec in properties.items():
        prop_type = prop_spec.get("type", "string")

        # Generate aggressive values based on type
        if prop_type == "string":
            args[prop_name] = generate_aggressive_text()
        elif prop_type == "integer":
            args[prop_name] = _generate_aggressive_integer()
        elif prop_type == "number":
            args[prop_name] = _generate_aggressive_float()
        elif prop_type == "boolean":
            # Use non-boolean values to test validation
            args[prop_name] = random.choice(
                [
                    None,
                    "",
                    "true",
                    "false",
                    0,
                    1,
                    -1,
                    42,
                    [],
                    {},
                    "yes",
                    "no",
                    "on",
                    "off",
                    "True",
                    "False",
                ]
            )
        elif prop_type == "array":
            # Generate malformed arrays
            aggressive_arrays = [
                None,  # Not an array
                "not_an_array",  # String instead
                [generate_aggressive_text() for _ in range(random.randint(0, 10))],
                [None] * random.randint(1, 5),  # Array of nulls
                [{}] * random.randint(1, 3),  # Array of empty objects
                [],  # Empty array
                ["A" * 10000],  # Huge string in array
                list(range(10000)),  # Huge array
            ]
            args[prop_name] = random.choice(aggressive_arrays)
        elif prop_type == "object":
            # Generate malformed objects
            aggressive_objects = [
                None,  # Not an object
                "not_an_object",  # String instead
                [],  # Array instead
                {},  # Empty object
                {generate_aggressive_text(): generate_aggressive_text()},
                {"evil": "<script>alert('xss')</script>"},
                {"\x00null\x00": "null_key"},
                {"a" * 1000: "huge_key"},
            ]
            args[prop_name] = random.choice(aggressive_objects)
        else:
            # Fallback for unknown types - try to break them
            args[prop_name] = random.choice(
                [
                    None,
                    generate_aggressive_text(),
                    _generate_aggressive_integer(),
                    _generate_aggressive_float(),
                    [],
                    {},
                ]
            )

    # Add some extra malicious fields that shouldn't be there
    malicious_extras = {
        "__proto__": {"isAdmin": True},
        "constructor": {"prototype": {"isAdmin": True}},
        "../injection": "path_traversal",
        "eval": "console.log('code injection')",
        "\x00null": "null_injection",
    }

    # Randomly add some malicious fields
    for key, value in malicious_extras.items():
        if random.random() < 0.3:  # 30% chance
            args[key] = value

    return args
