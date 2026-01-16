#!/usr/bin/env python3
"""
Aggressive Protocol Type Strategy

Helper functions for generating malicious/aggressive values
(used in tests and tool strategies).
"""

import random
from typing import Any

# Attack payloads
SQL_INJECTION = [
    "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
    "'; DELETE FROM table WHERE 1=1; --", "admin'--", "admin'/*",
    "' OR 1=1#", "' OR 'x'='x", "'; EXEC xp_cmdshell('dir'); --",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')", "<svg/onload=alert('xss')>",
    "<iframe src=javascript:alert('xss')>", "<body onload=alert('xss')>",
    "'><script>alert('xss')</script>", "\"><script>alert('xss')</script>",
    "<script>document.cookie</script>", "<script>window.location='http://evil.com'</script>",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..", "/etc/passwd",
    "/etc/shadow", "/etc/hosts", "C:\\windows\\system32\\drivers\\etc\\hosts",
    "file:///etc/passwd", "file:///c:/windows/system32/config/sam",
    "\\..\\..\\..\\..\\..\\..\\..\\..\\..",
]

OVERFLOW_VALUES = [
    "A" * 1000, "A" * 10000, "A" * 100000, "\x00" * 1000,
    "0" * 1000, "9" * 1000, " " * 1000, "\n" * 1000,
    "\t" * 1000, "漢" * 1000,
]

# Track how often experimental payloads are requested for deterministic test behavior
_experimental_payload_call_count = 0


def generate_malicious_string() -> str:
    """Generate malicious string values for aggressive testing."""
    strategies = [
        lambda: random.choice(SQL_INJECTION),
        lambda: random.choice(XSS_PAYLOADS),
        lambda: random.choice(PATH_TRAVERSAL),
        lambda: random.choice(OVERFLOW_VALUES),
        lambda: "\x00" * random.randint(1, 100),
        lambda: "A" * random.randint(1000, 10000),
        lambda: "漢字" * random.randint(100, 1000),
        lambda: random.choice(["", " ", "\t", "\n", "\r"]),
        lambda: f"http://evil.com/{random.choice(XSS_PAYLOADS)}",
    ]
    return random.choice(strategies)()


def generate_structured_string() -> str:
    """Generate a malicious string while preserving string type."""
    return random.choice([
        random.choice(SQL_INJECTION),
        random.choice(XSS_PAYLOADS),
        random.choice(PATH_TRAVERSAL),
        "A" * random.randint(256, 4096),
        "\x00" * random.randint(1, 64),
    ])


def generate_structured_number() -> int | float:
    """Generate an aggressive numeric value without NaN/Infinity."""
    return random.choice([
        -1, 0, 1, 2**31 - 1, 2**63 - 1, -2**63,
        10**9, -10**9, 3.14159, -3.14159,
    ])


def generate_structured_id() -> int | str:
    """Generate a JSON-RPC id that remains valid (string or number)."""
    return random.choice([
        1, 2, 42, 999999999, "req-001", "req-002", "id-" + ("A" * 32),
    ])


def generate_structured_meta() -> dict[str, Any]:
    """Generate a structured _meta object with aggressive values."""
    return {
        "trace": generate_structured_string(),
        "tags": [generate_structured_string() for _ in range(random.randint(1, 3))],
        "flags": {"experimental": random.choice([True, False])},
    }


def generate_structured_object() -> dict[str, Any]:
    """Generate a structured object with malicious strings/values."""
    return {
        "value": generate_structured_string(),
        "count": generate_structured_number(),
        "enabled": random.choice([True, False]),
    }


def choice_lazy(options):
    """Lazy choice that only evaluates the selected option."""
    picked = random.choice(options)
    return picked() if callable(picked) else picked


def generate_malicious_value() -> Any:
    """Generate malicious values of various types."""
    if random.random() < 0.2:
        return None
    return choice_lazy(
        [
            None,
            "",
            "null",
            "undefined",
            "NaN",
            "Infinity",
            "-Infinity",
            True,
            False,
            0,
            -1,
            999999999,
            -999999999,
            3.14159,
            -3.14159,
            [],
            {},
            lambda: generate_malicious_string(),
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            lambda: [generate_malicious_string()],
            lambda: {"evil": generate_malicious_string()},
        ]
    )


def generate_experimental_payload():
    """Generate experimental capability payloads lazily."""
    global _experimental_payload_call_count
    _experimental_payload_call_count += 1
    if _experimental_payload_call_count % 5 == 0:
        return None
    return choice_lazy([
        None, "", [], lambda: generate_malicious_string(),
        lambda: random.randint(-1000, 1000),
        lambda: random.choice([True, False]),
        lambda: {
            "customCapability": generate_malicious_value(),
            "extendedFeature": {
                "enabled": generate_malicious_value(),
                "config": generate_malicious_value(),
            },
            "__proto__": {"isAdmin": True},
            "evil": generate_malicious_string(),
        },
        lambda: {
            "maliciousExtension": {
                "payload": generate_malicious_string(),
                "injection": random.choice(SQL_INJECTION),
                "xss": random.choice(XSS_PAYLOADS),
            }
        },
        lambda: ["item1", "item2", generate_malicious_value()],
        lambda: {"nested": {"key": generate_malicious_value()}},
        "experimental_string_value",
        {"feature_flag": True},
        lambda: [1, 2, 3, "mixed_array"],
        {"config": {"debug": False, "verbose": True}},
    ])
