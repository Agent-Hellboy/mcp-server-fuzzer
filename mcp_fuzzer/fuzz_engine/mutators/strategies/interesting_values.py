#!/usr/bin/env python3
"""
Curated Values for Smart Fuzzing

This module contains carefully selected constants for schema-aware fuzzing:
- REALISTIC: Schema-valid boundary values for testing business logic
- AGGRESSIVE: Attack payloads for testing security and validation

Based on AFL mutation strategies, OWASP testing patterns, and property-based testing.
"""

import random
from typing import Any

# ============================================================================
# REALISTIC PHASE: Schema-valid boundary values
# ============================================================================

# Zero-crossing integers (always valid, test edge cases)
BOUNDARY_INTS_SMALL: list[int] = [0, 1, -1]

# AFL-style interesting integers (within typical signed ranges)
BOUNDARY_INTS_MEDIUM: list[int] = [
    0, -1, 1,
    127, 128,       # int8 boundary
    255, 256,       # uint8 boundary
    32767, 32768,   # int16 boundary
    65535, 65536,   # uint16 boundary
]

BOUNDARY_INTS_LARGE: list[int] = [
    2147483647,     # INT32_MAX
    -2147483648,    # INT32_MIN
]

# Short valid strings for boundary testing
BOUNDARY_STRINGS: list[str] = [
    "",             # empty
    "a",            # single char
    "test",         # short word
    "valid_value",  # underscore
    "test-value",   # hyphen
    "Test123",      # mixed case + digits
]

# Realistic sample values by semantic context
REALISTIC_SAMPLES: dict[str, list[str]] = {
    "name": ["John", "Alice", "Test User", "Admin"],
    "id": ["1", "123", "abc-123", "user_001"],
    "query": ["search term", "test query", "example"],
    "path": ["/home", "/tmp", "/var/log", "documents/file.txt"],
    "url": ["https://example.com", "http://localhost:8080", "https://api.test.org/v1"],
    "email": ["test@example.com", "user@domain.org", "admin@localhost"],
}


# ============================================================================
# AGGRESSIVE PHASE: Attack payloads
# ============================================================================

# SQL injection payloads (various DB dialects)
SQL_INJECTION: list[str] = [
    "' OR '1'='1",
    "'; DROP TABLE--",
    "' OR 1=1#",
    "admin'--",
    "' UNION SELECT NULL--",
    "1; DELETE FROM",
    "' OR ''='",
]

# NoSQL injection payloads (MongoDB-style operators)
NOSQL_INJECTION: list[str] = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "this.password.length > 0"}',
    '{"$exists": true}',
    '{"$or": [{"role":"admin"},{"role":{"$ne":"user"}}]}',
]

# XSS payloads (HTML/JS injection)
XSS_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
]

# Path traversal payloads
PATH_TRAVERSAL: list[str] = [
    "../",
    "..\\",
    "%2e%2e%2f",
    "....//",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
]

# Command injection payloads
COMMAND_INJECTION: list[str] = [
    "; ls",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "; echo test",
    "& dir",
]

# SSRF payloads
SSRF_PAYLOADS: list[str] = [
    "http://localhost",
    "http://127.0.0.1",
    "http://[::1]",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "http://169.254.169.254",  # AWS metadata
]

# Unicode tricks for validation bypass
UNICODE_TRICKS: list[str] = [
    "\x00",         # Null byte
    "\u200b",       # Zero-width space
    "\u202e",       # RTL override
    "\ufeff",       # BOM
    "\u0000",       # Unicode null
    "\u00a0",       # Non-breaking space
]

# Homoglyphs (visually similar characters)
HOMOGLYPHS: dict[str, str] = {
    "a": "а",       # Cyrillic 'a'
    "e": "е",       # Cyrillic 'e'
    "o": "о",       # Cyrillic 'o'
    "c": "с",       # Cyrillic 'c'
    "p": "р",       # Cyrillic 'p'
}

# Encoding bypass payloads
ENCODING_BYPASS: list[str] = [
    "%00",          # URL-encoded null
    "%2e%2e",       # URL-encoded ..
    "&#x3c;",       # HTML entity <
    "\\u003c",      # JSON unicode escape <
    "%252e",        # Double URL encoding
    "%%32%65",      # Mixed encoding
]

# Type confusion values (strings that look like other types)
TYPE_CONFUSION: list[str] = [
    "123",          # Numeric string
    "true",         # Boolean string
    "false",
    "null",
    "undefined",
    "NaN",
    "Infinity",
    "[]",           # Array string
    "{}",           # Object string
    "[object Object]",
]

# Integer overflow/underflow values
OVERFLOW_INTS: list[int] = [
    2147483647,     # INT32_MAX
    2147483648,     # INT32_MAX + 1
    -2147483648,    # INT32_MIN
    -2147483649,    # INT32_MIN - 1
    9223372036854775807,   # INT64_MAX
    -9223372036854775808,  # INT64_MIN
]

# Special float values
SPECIAL_FLOATS: list[float] = [
    0.0,
    -0.0,
    float("inf"),
    float("-inf"),
    1e308,          # Near max float
    1e-308,         # Near min positive float
]


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_boundary_values_for_range(minimum: int, maximum: int) -> list[int]:
    """Get boundary values within a specific range."""
    candidates = [
        minimum,
        minimum + 1,
        maximum - 1,
        maximum,
        (minimum + maximum) // 2,
        0, 1, -1,
    ]
    return [v for v in candidates if minimum <= v <= maximum]


def get_payload_within_length(max_length: int, category: str = "sql") -> str:
    """Get an attack payload that fits within the length constraint."""
    payloads_map: dict[str, list[str]] = {
        "sql": SQL_INJECTION,
        "nosql": NOSQL_INJECTION,
        "xss": XSS_PAYLOADS,
        "path": PATH_TRAVERSAL,
        "command": COMMAND_INJECTION,
        "ssrf": SSRF_PAYLOADS,
    }
    
    payloads = payloads_map.get(category, SQL_INJECTION)
    
    # Find payload that fits
    for payload in payloads:
        if len(payload) <= max_length:
            return payload
    
    # Truncate shortest if none fit
    shortest = min(payloads, key=len)
    return shortest[:max_length] if max_length > 0 else ""


def inject_unicode_trick(value: str, max_length: int | None = None) -> str:
    """Embed a unicode trick into a value."""
    non_ascii = [
        trick for trick in UNICODE_TRICKS if any(ord(ch) > 127 for ch in trick)
    ]
    choices = non_ascii or UNICODE_TRICKS
    if not value:
        return random.choice(choices)
    
    trick = random.choice(choices)
    mid = len(value) // 2
    result = value[:mid] + trick + value[mid:]
    
    if max_length is not None and len(result) > max_length:
        return result[:max_length]
    return result


def get_off_by_one_string(max_length: int) -> str:
    """Generate a string that is one character over the limit."""
    return "a" * (max_length + 1)


def get_off_by_one_int(maximum: int | None = None, minimum: int | None = None) -> int:
    """Generate an integer that is off-by-one from the boundary."""
    if maximum is not None:
        return maximum + 1
    if minimum is not None:
        return minimum - 1
    return 2147483648  # INT32_MAX + 1


def get_realistic_boundary_string(
    min_length: int,
    max_length: int,
    run_index: int = 0,
) -> str:
    """Generate a schema-valid boundary string for realistic testing."""
    boundaries = [
        min_length,
        max_length,
        (min_length + max_length) // 2,
        min(min_length + 1, max_length),
        max(max_length - 1, min_length),
    ]
    target = boundaries[run_index % len(boundaries)]
    return "a" * target


def get_realistic_boundary_int(
    minimum: int,
    maximum: int,
    run_index: int = 0,
) -> int:
    """Generate a schema-valid boundary integer for realistic testing."""
    boundaries = get_boundary_values_for_range(minimum, maximum)
    if not boundaries:
        return minimum
    return boundaries[run_index % len(boundaries)]


def cycle_enum_values(enum_values: list[Any], run_index: int = 0) -> Any:
    """Deterministically cycle through all enum values."""
    if not enum_values:
        return None
    return enum_values[run_index % len(enum_values)]
