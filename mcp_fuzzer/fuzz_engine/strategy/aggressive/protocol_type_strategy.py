#!/usr/bin/env python3
"""
Aggressive Protocol Type Strategy

This module provides strategies for generating malicious, malformed, and edge-case
protocol messages. Used in the aggressive phase to test server security and
robustness with attack vectors.
"""

import random
from typing import Any, Dict

# Attack payloads from tool strategy
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


def _generate_malicious_string() -> str:
    """Generate malicious string values for aggressive testing."""
    strategies = [
        lambda: random.choice(SQL_INJECTION),
        lambda: random.choice(XSS_PAYLOADS),
        lambda: random.choice(PATH_TRAVERSAL),
        lambda: random.choice(OVERFLOW_VALUES),
        lambda: "\x00" * random.randint(1, 100),  # Null bytes
        lambda: "A" * random.randint(1000, 10000),  # Overflow
        lambda: "漢字" * random.randint(100, 1000),  # Unicode overflow
        lambda: random.choice(["", " ", "\t", "\n", "\r"]),  # Empty/whitespace
        lambda: f"http://evil.com/{random.choice(XSS_PAYLOADS)}",  # URLs with XSS
    ]

    return random.choice(strategies)()


def _generate_malicious_value() -> Any:
    """Generate malicious values of various types."""
    return random.choice(
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
            _generate_malicious_string(),
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            [_generate_malicious_string()],
            {"evil": _generate_malicious_string()},
        ]
    )


def fuzz_initialize_request_aggressive() -> Dict[str, Any]:
    """Generate aggressive InitializeRequest for security/robustness testing."""
    # Malicious protocol versions
    malicious_versions = [
        _generate_malicious_string(),
        None,
        "",
        "999.999.999",
        "-1.0.0",
        random.choice(SQL_INJECTION),
        random.choice(XSS_PAYLOADS),
        random.choice(PATH_TRAVERSAL),
        "A" * 1000,  # Overflow
        "\x00\x01\x02",  # Null bytes
    ]

    # Malicious JSON-RPC IDs
    malicious_ids = [
        _generate_malicious_value(),
        {"evil": "object_as_id"},
        [1, 2, 3],  # Array as ID
        float("inf"),
        float("-inf"),
        2**63,  # Large number
        -(2**63),  # Large negative number
    ]

    # Malicious method names
    malicious_methods = [
        _generate_malicious_string(),
        None,
        "",
        random.choice(PATH_TRAVERSAL),
        "eval()",
        "system('rm -rf /')",
        "__proto__",
        "constructor",
        "prototype",
        "\x00null\x00",
    ]

    # Build malicious request
    base_request = {
        "jsonrpc": random.choice(
            [
                "2.0",  # Valid
                "1.0",  # Invalid version
                "3.0",  # Future version
                None,  # Missing
                "",  # Empty
                _generate_malicious_string(),  # Malicious
            ]
        ),
        "id": random.choice(malicious_ids),
        "method": random.choice(malicious_methods),
    }

    # Malicious params
    malicious_params = random.choice(
        [
            None,  # Missing params
            "",  # Empty string instead of object
            [],  # Array instead of object
            _generate_malicious_string(),  # String instead of object
            {
                "protocolVersion": random.choice(malicious_versions),
                "capabilities": random.choice(
                    [
                        None,
                        "",
                        [],
                        _generate_malicious_string(),
                        {"__proto__": {"isAdmin": True}},
                        {"constructor": {"prototype": {"isAdmin": True}}},
                        {"evil": _generate_malicious_string()},
                    ]
                ),
                "clientInfo": random.choice(
                    [
                        None,
                        "",
                        [],
                        _generate_malicious_string(),
                        {
                            "name": _generate_malicious_string(),
                            "version": _generate_malicious_string(),
                            "__proto__": {"isAdmin": True},
                            "evil": _generate_malicious_string(),
                        },
                    ]
                ),
                # Add extra malicious fields
                "__proto__": {"isAdmin": True},
                "constructor": {"prototype": {"isAdmin": True}},
                "eval": "console.log('injection')",
                "../injection": "path_traversal",
                "\x00null": "null_injection",
            },
        ]
    )

    if malicious_params is not None and isinstance(malicious_params, dict):
        base_request["params"] = malicious_params

    # Randomly add extra malicious top-level fields
    malicious_extras = {
        "__proto__": {"isAdmin": True},
        "constructor": {"prototype": {"isAdmin": True}},
        "eval": "system('echo pwned')",
        "exec": "rm -rf /",
        "../injection": "path_traversal",
        "admin": True,
        "isAdmin": True,
        "root": True,
        "user": "admin",
        "password": "password123",
        "\x00null": "null_injection",
        "evil": _generate_malicious_string(),
    }

    for key, value in malicious_extras.items():
        if random.random() < 0.3:  # 30% chance to add each
            base_request[key] = value

    return base_request


def fuzz_progress_notification() -> Dict[str, Any]:
    """Fuzz ProgressNotification with edge cases."""
    # Generate AGGRESSIVE progress tokens to break things
    progress_token_options = [
        _generate_malicious_value(),
        "",
        None,
        "\U0001f680\U0001f525\U0001f4af",
        "A" * 1000,
        float("inf"),
        float("nan"),
        "' OR 1=1; --",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "\x00\x01\x02\x03",  # Null bytes
    ]

    return {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": random.choice(progress_token_options),
            "progress": _generate_malicious_value(),
            "total": _generate_malicious_value(),
        },
    }


def fuzz_cancel_notification() -> Dict[str, Any]:
    """Fuzz CancelNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": _generate_malicious_value(),
            "reason": _generate_malicious_string(),
        },
    }


def fuzz_list_resources_request() -> Dict[str, Any]:
    """Fuzz ListResourcesRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "resources/list",
        "params": {
            "cursor": _generate_malicious_string(),
            "_meta": _generate_malicious_value(),
        },
    }


def fuzz_read_resource_request() -> Dict[str, Any]:
    """Fuzz ReadResourceRequest with edge cases."""
    malicious_uris = [
        "file:///etc/passwd",
        "file:///c:/windows/system32/config/sam",
        "../../../etc/passwd",
        "javascript:alert('xss')",
        "<script>alert('xss')</script>",
        "data:text/html,<script>alert('xss')</script>",
        "file://" + "A" * 1000,
        "\x00\x01\x02\x03",
    ]

    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "resources/read",
        "params": {
            "uri": random.choice(malicious_uris + [_generate_malicious_string()])
        },
    }


def fuzz_set_level_request() -> Dict[str, Any]:
    """Fuzz SetLevelRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "logging/setLevel",
        "params": {"level": _generate_malicious_value()},
    }


def fuzz_generic_jsonrpc_request() -> Dict[str, Any]:
    """Fuzz generic JSON-RPC requests with edge cases."""
    return {
        "jsonrpc": random.choice(["2.0", "1.0", "3.0", "invalid", "", None]),
        "id": _generate_malicious_value(),
        "method": _generate_malicious_string(),
        "params": _generate_malicious_value(),
    }


def fuzz_call_tool_result() -> Dict[str, Any]:
    """Fuzz CallToolResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "result": {
            "content": [
                {
                    "type": _generate_malicious_string(),
                    "data": _generate_malicious_string(),
                }
            ],
            "isError": _generate_malicious_value(),
            "_meta": _generate_malicious_value(),
        },
    }


def fuzz_sampling_message() -> Dict[str, Any]:
    """Fuzz SamplingMessage with edge cases."""
    return {
        "role": _generate_malicious_string(),
        "content": [
            {"type": _generate_malicious_string(), "data": _generate_malicious_string()}
        ],
    }


def fuzz_create_message_request() -> Dict[str, Any]:
    """Fuzz CreateMessageRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "sampling/createMessage",
        "params": {
            "messages": [fuzz_sampling_message() for _ in range(random.randint(0, 5))],
            "modelPreferences": _generate_malicious_value(),
            "systemPrompt": _generate_malicious_string(),
            "includeContext": _generate_malicious_string(),
            "temperature": _generate_malicious_value(),
            "maxTokens": _generate_malicious_value(),
            "stopSequences": _generate_malicious_value(),
            "metadata": _generate_malicious_value(),
        },
    }


def fuzz_list_prompts_request() -> Dict[str, Any]:
    """Fuzz ListPromptsRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "prompts/list",
        "params": {
            "cursor": _generate_malicious_string(),
            "_meta": _generate_malicious_value(),
        },
    }


def fuzz_get_prompt_request() -> Dict[str, Any]:
    """Fuzz GetPromptRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "prompts/get",
        "params": {
            "name": _generate_malicious_string(),
            "arguments": _generate_malicious_value(),
        },
    }


def fuzz_list_roots_request() -> Dict[str, Any]:
    """Fuzz ListRootsRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "roots/list",
        "params": {"_meta": _generate_malicious_value()},
    }


def fuzz_subscribe_request() -> Dict[str, Any]:
    """Fuzz SubscribeRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "resources/subscribe",
        "params": {"uri": _generate_malicious_string()},
    }


def fuzz_unsubscribe_request() -> Dict[str, Any]:
    """Fuzz UnsubscribeRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "resources/unsubscribe",
        "params": {"uri": _generate_malicious_string()},
    }


def fuzz_complete_request() -> Dict[str, Any]:
    """Fuzz CompleteRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": _generate_malicious_value(),
        "method": "completion/complete",
        "params": {
            "ref": _generate_malicious_value(),
            "argument": _generate_malicious_value(),
        },
    }


def get_protocol_fuzzer_method(protocol_type: str):
    """Get the fuzzer method for a specific protocol type."""
    fuzzer_methods = {
        "InitializeRequest": fuzz_initialize_request_aggressive,
        "ProgressNotification": fuzz_progress_notification,
        "CancelNotification": fuzz_cancel_notification,
        "ListResourcesRequest": fuzz_list_resources_request,
        "ReadResourceRequest": fuzz_read_resource_request,
        "SetLevelRequest": fuzz_set_level_request,
        "GenericJSONRPCRequest": fuzz_generic_jsonrpc_request,
        "CallToolResult": fuzz_call_tool_result,
        "SamplingMessage": fuzz_sampling_message,
        "CreateMessageRequest": fuzz_create_message_request,
        "ListPromptsRequest": fuzz_list_prompts_request,
        "GetPromptRequest": fuzz_get_prompt_request,
        "ListRootsRequest": fuzz_list_roots_request,
        "SubscribeRequest": fuzz_subscribe_request,
        "UnsubscribeRequest": fuzz_unsubscribe_request,
        "CompleteRequest": fuzz_complete_request,
    }

    return fuzzer_methods.get(protocol_type)
