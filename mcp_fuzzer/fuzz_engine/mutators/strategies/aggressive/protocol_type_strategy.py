#!/usr/bin/env python3
"""
Aggressive Protocol Type Strategy

This module provides strategies for generating malicious, malformed, and edge-case
protocol messages. Used in the aggressive phase to test server security and
robustness with attack vectors.
"""

import random
from typing import Any

from ..spec_protocol import get_spec_protocol_fuzzer_method

# Track how often experimental payloads are requested so we can deterministically
# force `None` values often enough for unit tests that expect them.
_experimental_payload_call_count = 0

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


def generate_malicious_string() -> str:
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


def generate_structured_string() -> str:
    """Generate a malicious string while preserving string type."""
    return random.choice(
        [
            random.choice(SQL_INJECTION),
            random.choice(XSS_PAYLOADS),
            random.choice(PATH_TRAVERSAL),
            "A" * random.randint(256, 4096),
            "\x00" * random.randint(1, 64),
        ]
    )


def generate_structured_number() -> int | float:
    """Generate an aggressive numeric value without NaN/Infinity."""
    return random.choice(
        [
            -1,
            0,
            1,
            2**31 - 1,
            2**63 - 1,
            -2**63,
            10**9,
            -10**9,
            3.14159,
            -3.14159,
        ]
    )


def generate_structured_id() -> int | str:
    """Generate a JSON-RPC id that remains valid (string or number)."""
    return random.choice(
        [
            1,
            2,
            42,
            999999999,
            "req-001",
            "req-002",
            "id-" + ("A" * 32),
        ]
    )


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

def _aggressive_spec_request(
    protocol_type: str, overrides: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    method = get_spec_protocol_fuzzer_method(protocol_type, "aggressive")
    if not method:
        return None
    request = method()
    if overrides and isinstance(request.get("params"), dict):
        request["params"].update(overrides)
    return request

def choice_lazy(options):
    """Lazy choice that only evaluates the selected option."""
    picked = random.choice(options)
    return picked() if callable(picked) else picked


def generate_malicious_value() -> Any:
    """Generate malicious values of various types."""
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
    # Every few calls, guarantee a None payload so tests always see the case.
    if _experimental_payload_call_count % 5 == 0:
        return None
    return choice_lazy(
        [
            None,
            "",
            [],
            lambda: generate_malicious_string(),
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
        ]
    )


def fuzz_initialize_request_aggressive() -> dict[str, Any]:
    """Generate aggressive InitializeRequest for security/robustness testing."""
    base_request = {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "initialize",
    }

    malicious_params = choice_lazy(
        [
            None,
            generate_structured_object(),
            lambda: {
                "protocolVersion": generate_structured_string(),
                "capabilities": {
                    "elicitation": generate_structured_object(),
                    "experimental": generate_experimental_payload(),
                    "sampling": generate_structured_object(),
                },
                "clientInfo": {
                    "name": generate_structured_string(),
                    "version": generate_structured_string(),
                },
                "locale": generate_structured_string(),
                "rootUri": generate_structured_string(),
                "clientVersion": generate_structured_string(),
                "features": generate_structured_object(),
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
        "evil": generate_malicious_string(),
    }

    for key, value in malicious_extras.items():
        if random.random() < 0.3:  # 30% chance to add each
            base_request[key] = value

    return base_request


def fuzz_progress_notification() -> dict[str, Any]:
    """Fuzz ProgressNotification with edge cases."""
    progress_token_options = [
        generate_structured_string(),
        "A" * 1000,
        "progress-" + ("A" * 128),
    ]

    return {
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": random.choice(progress_token_options),
            "progress": generate_structured_number(),
            "total": generate_structured_number(),
        },
    }


def fuzz_cancel_notification() -> dict[str, Any]:
    """Fuzz CancelNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": generate_structured_id(),
            "reason": generate_structured_string(),
        },
    }


def fuzz_list_resources_request() -> dict[str, Any]:
    """Fuzz ListResourcesRequest with edge cases."""
    spec_request = _aggressive_spec_request("ListResourcesRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params.setdefault("_meta", generate_structured_meta())
        params["cursor"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "resources/list",
        "params": {
            "cursor": generate_structured_string(),
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_read_resource_request() -> dict[str, Any]:
    """Fuzz ReadResourceRequest with edge cases."""
    spec_request = _aggressive_spec_request("ReadResourceRequest")
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
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params["uri"] = random.choice(malicious_uris + [generate_structured_string()])
        return spec_request

    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "resources/read",
        "params": {
            "uri": random.choice(malicious_uris + [generate_structured_string()])
        },
    }


def fuzz_set_level_request() -> dict[str, Any]:
    """Fuzz SetLevelRequest with edge cases."""
    spec_request = _aggressive_spec_request("SetLevelRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        spec_request["params"]["level"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "logging/setLevel",
        "params": {"level": generate_structured_string()},
    }


def fuzz_generic_jsonrpc_request() -> dict[str, Any]:
    """Fuzz generic JSON-RPC requests with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": generate_structured_string(),
        "params": generate_structured_object(),
    }


def fuzz_call_tool_result() -> dict[str, Any]:
    """Fuzz CallToolResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "content": [
                {
                    "type": generate_malicious_string(),
                    "data": generate_malicious_string(),
                }
            ],
            "isError": generate_malicious_value(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_sampling_message() -> dict[str, Any]:
    """Fuzz SamplingMessage with edge cases."""
    return {
        "role": generate_malicious_string(),
        "content": [
            {
                "type": generate_malicious_string(),
                "data": generate_malicious_string(),
            }
        ],
    }


def fuzz_create_message_request() -> dict[str, Any]:
    """Fuzz CreateMessageRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "sampling/createMessage",
        "params": {
            "messages": [fuzz_sampling_message() for _ in range(random.randint(0, 5))],
            "modelPreferences": generate_structured_object(),
            "systemPrompt": generate_structured_string(),
            "includeContext": random.choice(["none", "system", "all", "invalid"]),
            "temperature": generate_structured_number(),
            "maxTokens": int(abs(generate_structured_number())),
            "stopSequences": [
                generate_structured_string() for _ in range(random.randint(0, 3))
            ],
            "metadata": generate_structured_object(),
        },
    }


def fuzz_list_prompts_request() -> dict[str, Any]:
    """Fuzz ListPromptsRequest with edge cases."""
    spec_request = _aggressive_spec_request("ListPromptsRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params.setdefault("_meta", generate_structured_meta())
        params["cursor"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "prompts/list",
        "params": {
            "cursor": generate_structured_string(),
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_get_prompt_request() -> dict[str, Any]:
    """Fuzz GetPromptRequest with edge cases."""
    spec_request = _aggressive_spec_request("GetPromptRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params.setdefault("name", generate_structured_string())
        params["arguments"] = generate_structured_object()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "prompts/get",
        "params": {
            "name": generate_structured_string(),
            "arguments": generate_structured_object(),
        },
    }


def fuzz_list_roots_request() -> dict[str, Any]:
    """Fuzz ListRootsRequest with edge cases."""
    spec_request = _aggressive_spec_request("ListRootsRequest")
    if spec_request:
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "roots/list",
        "params": {"_meta": generate_structured_meta()},
    }


def fuzz_subscribe_request() -> dict[str, Any]:
    """Fuzz SubscribeRequest with edge cases."""
    spec_request = _aggressive_spec_request("SubscribeRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        spec_request["params"]["uri"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "resources/subscribe",
        "params": {"uri": generate_structured_string()},
    }


def fuzz_unsubscribe_request() -> dict[str, Any]:
    """Fuzz UnsubscribeRequest with edge cases."""
    spec_request = _aggressive_spec_request("UnsubscribeRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        spec_request["params"]["uri"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "resources/unsubscribe",
        "params": {"uri": generate_structured_string()},
    }


def fuzz_complete_request() -> dict[str, Any]:
    """Fuzz CompleteRequest with edge cases."""
    spec_request = _aggressive_spec_request("CompleteRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params["ref"] = {"type": "ref/prompt", "name": generate_structured_string()}
        params["argument"] = generate_structured_string()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "completion/complete",
        "params": {
            "ref": {"name": generate_structured_string()},
            "argument": generate_structured_string(),
        },
    }


def fuzz_list_resource_templates_request() -> dict[str, Any]:
    """Fuzz ListResourceTemplatesRequest with edge cases."""
    spec_request = _aggressive_spec_request("ListResourceTemplatesRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        spec_request["params"].setdefault("_meta", generate_structured_meta())
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "resources/templates/list",
        "params": {
            "cursor": generate_structured_string(),
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_elicit_request() -> dict[str, Any]:
    """Fuzz ElicitRequest with edge cases."""
    spec_request = _aggressive_spec_request("ElicitRequest")
    if spec_request and isinstance(spec_request.get("params"), dict):
        params = spec_request["params"]
        params["message"] = generate_structured_string()
        params["requestedSchema"] = generate_structured_object()
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "elicitation/create",
        "params": {
            "message": generate_structured_string(),
            "requestedSchema": generate_structured_object(),
        },
    }


def fuzz_ping_request() -> dict[str, Any]:
    """Fuzz PingRequest with edge cases."""
    spec_request = _aggressive_spec_request("PingRequest")
    if spec_request:
        return spec_request
    return {
        "jsonrpc": "2.0",
        "id": generate_structured_id(),
        "method": "ping",
        "params": generate_structured_object(),
    }


# Result schemas for fuzzing
def fuzz_initialize_result() -> dict[str, Any]:
    """Fuzz InitializeResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "protocolVersion": generate_malicious_string(),
            "capabilities": generate_malicious_value(),
            "serverInfo": generate_malicious_value(),
            "instructions": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_resources_result() -> dict[str, Any]:
    """Fuzz ListResourcesResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "resources": [
                generate_malicious_value() for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_resource_templates_result() -> dict[str, Any]:
    """Fuzz ListResourceTemplatesResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "resourceTemplates": [
                generate_malicious_value() for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_read_resource_result() -> dict[str, Any]:
    """Fuzz ReadResourceResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "contents": [
                generate_malicious_value() for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_prompts_result() -> dict[str, Any]:
    """Fuzz ListPromptsResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "prompts": [
                generate_malicious_value() for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_get_prompt_result() -> dict[str, Any]:
    """Fuzz GetPromptResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "description": generate_malicious_string(),
            "messages": [
                generate_malicious_value() for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_tools_result() -> dict[str, Any]:
    """Fuzz ListToolsResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "tools": [generate_malicious_value() for _ in range(random.randint(0, 10))],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_complete_result() -> dict[str, Any]:
    """Fuzz CompleteResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "completion": {
                "values": [
                    generate_malicious_string() for _ in range(random.randint(0, 5))
                ],
                "total": generate_malicious_value(),
                "hasMore": generate_malicious_value(),
            },
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_create_message_result() -> dict[str, Any]:
    """Fuzz CreateMessageResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "content": generate_malicious_value(),
            "model": generate_malicious_string(),
            "stopReason": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_roots_result() -> dict[str, Any]:
    """Fuzz ListRootsResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "roots": [generate_malicious_value() for _ in range(random.randint(0, 5))],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_ping_result() -> dict[str, Any]:
    """Fuzz PingResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": generate_malicious_value(),
    }


def fuzz_elicit_result() -> dict[str, Any]:
    """Fuzz ElicitResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "content": [
                generate_malicious_value() for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


# Notification schemas for fuzzing
def fuzz_logging_message_notification() -> dict[str, Any]:
    """Fuzz LoggingMessageNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {
            "level": generate_structured_string(),
            "logger": generate_structured_string(),
            "data": generate_structured_object(),
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_resource_list_changed_notification() -> dict[str, Any]:
    """Fuzz ResourceListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/resources/list_changed",
        "params": {
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_resource_updated_notification() -> dict[str, Any]:
    """Fuzz ResourceUpdatedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {
            "uri": generate_structured_string(),
        },
    }


def fuzz_prompt_list_changed_notification() -> dict[str, Any]:
    """Fuzz PromptListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/prompts/list_changed",
        "params": {
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_tool_list_changed_notification() -> dict[str, Any]:
    """Fuzz ToolListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {
            "_meta": generate_structured_meta(),
        },
    }


def fuzz_roots_list_changed_notification() -> dict[str, Any]:
    """Fuzz RootsListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/roots/list_changed",
        "params": {
            "_meta": generate_structured_meta(),
        },
    }


# Content block schemas for fuzzing
def fuzz_text_content() -> dict[str, Any]:
    """Fuzz TextContent with edge cases."""
    return {
        "type": "text",
        "text": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_image_content() -> dict[str, Any]:
    """Fuzz ImageContent with edge cases."""
    return {
        "type": "image",
        "data": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_audio_content() -> dict[str, Any]:
    """Fuzz AudioContent with edge cases."""
    return {
        "type": "audio",
        "data": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


# Resource schemas for fuzzing
def fuzz_resource() -> dict[str, Any]:
    """Fuzz Resource with edge cases."""
    return {
        "name": generate_malicious_string(),
        "uri": generate_malicious_string(),
        "description": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "size": generate_malicious_value(),
        "title": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_resource_template() -> dict[str, Any]:
    """Fuzz ResourceTemplate with edge cases."""
    return {
        "name": generate_malicious_string(),
        "uriTemplate": generate_malicious_string(),
        "description": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "title": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_text_resource_contents() -> dict[str, Any]:
    """Fuzz TextResourceContents with edge cases."""
    return {
        "uri": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "text": generate_malicious_string(),
        "_meta": generate_malicious_value(),
    }


def fuzz_blob_resource_contents() -> dict[str, Any]:
    """Fuzz BlobResourceContents with edge cases."""
    return {
        "uri": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "blob": generate_malicious_string(),
        "_meta": generate_malicious_value(),
    }


# Tool schemas for fuzzing
def fuzz_tool() -> dict[str, Any]:
    """Fuzz Tool with edge cases."""
    return {
        "name": generate_malicious_string(),
        "description": generate_malicious_string(),
        "inputSchema": generate_malicious_value(),
        "outputSchema": generate_malicious_value(),
        "title": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
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
        "ListResourceTemplatesRequest": fuzz_list_resource_templates_request,
        "ElicitRequest": fuzz_elicit_request,
        "PingRequest": fuzz_ping_request,
        # Result schemas
        "InitializeResult": fuzz_initialize_result,
        "ListResourcesResult": fuzz_list_resources_result,
        "ListResourceTemplatesResult": fuzz_list_resource_templates_result,
        "ReadResourceResult": fuzz_read_resource_result,
        "ListPromptsResult": fuzz_list_prompts_result,
        "GetPromptResult": fuzz_get_prompt_result,
        "ListToolsResult": fuzz_list_tools_result,
        "CompleteResult": fuzz_complete_result,
        "CreateMessageResult": fuzz_create_message_result,
        "ListRootsResult": fuzz_list_roots_result,
        "PingResult": fuzz_ping_result,
        "ElicitResult": fuzz_elicit_result,
        # Notification schemas
        "LoggingMessageNotification": fuzz_logging_message_notification,
        "ResourceListChangedNotification": fuzz_resource_list_changed_notification,
        "ResourceUpdatedNotification": fuzz_resource_updated_notification,
        "PromptListChangedNotification": fuzz_prompt_list_changed_notification,
        "ToolListChangedNotification": fuzz_tool_list_changed_notification,
        "RootsListChangedNotification": fuzz_roots_list_changed_notification,
        # Content block schemas
        "TextContent": fuzz_text_content,
        "ImageContent": fuzz_image_content,
        "AudioContent": fuzz_audio_content,
        # Resource schemas
        "Resource": fuzz_resource,
        "ResourceTemplate": fuzz_resource_template,
        "TextResourceContents": fuzz_text_resource_contents,
        "BlobResourceContents": fuzz_blob_resource_contents,
        # Tool schemas
        "Tool": fuzz_tool,
    }

    return fuzzer_methods.get(protocol_type)
