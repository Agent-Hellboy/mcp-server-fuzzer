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


def generate_malicious_value() -> Any:
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
            generate_malicious_string(),
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            [generate_malicious_string()],
            {"evil": generate_malicious_string()},
        ]
    )


def fuzz_initialize_request_aggressive() -> Dict[str, Any]:
    """Generate aggressive InitializeRequest for security/robustness testing."""
    # Malicious protocol versions
    malicious_versions = [
        generate_malicious_string(),
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
        generate_malicious_value(),
        {"evil": "object_as_id"},
        [1, 2, 3],  # Array as ID
        float("inf"),
        float("-inf"),
        2**63,  # Large number
        -(2**63),  # Large negative number
    ]

    # Malicious method names
    malicious_methods = [
        generate_malicious_string(),
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
                generate_malicious_string(),  # Malicious
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
            generate_malicious_string(),  # String instead of object
            {
                "protocolVersion": random.choice(malicious_versions),
                "capabilities": random.choice(
                    [
                        None,
                        "",
                        [],
                        generate_malicious_string(),
                        {"__proto__": {"isAdmin": True}},
                        {"constructor": {"prototype": {"isAdmin": True}}},
                        {"evil": generate_malicious_string()},
                        {
                            "experimental": random.choice(
                                [
                                    None,
                                    "",
                                    [],
                                    generate_malicious_string(),
                                    random.randint(-1000, 1000),
                                    random.choice([True, False]),
                                    {
                                        "customCapability": generate_malicious_value(),
                                        "extendedFeature": {
                                            "enabled": generate_malicious_value(),
                                            "config": generate_malicious_value(),
                                        },
                                        "__proto__": {"isAdmin": True},
                                        "evil": generate_malicious_string(),
                                    },
                                    {
                                        "maliciousExtension": {
                                            "payload": generate_malicious_string(),
                                            "injection": random.choice(SQL_INJECTION),
                                            "xss": random.choice(XSS_PAYLOADS),
                                        }
                                    },
                                    # Add arrays and nested objects for more variety
                                    ["item1", "item2", generate_malicious_value()],
                                    {"nested": {"key": generate_malicious_value()}},
                                    "experimental_string_value",
                                    {"feature_flag": True},
                                    [1, 2, 3, "mixed_array"],
                                    {"config": {"debug": False, "verbose": True}},
                                ]
                            )
                        },
                    ]
                ),
                "clientInfo": random.choice(
                    [
                        None,
                        "",
                        [],
                        generate_malicious_string(),
                        {
                            "name": generate_malicious_string(),
                            "version": generate_malicious_string(),
                            "__proto__": {"isAdmin": True},
                            "evil": generate_malicious_string(),
                        },
                    ]
                ),
                "experimental": random.choice(
                    [
                        None,
                        "",
                        [],
                        generate_malicious_string(),
                        {
                            "customCapability": generate_malicious_value(),
                            "extendedFeature": {
                                "enabled": generate_malicious_value(),
                                "config": generate_malicious_value(),
                            },
                            "__proto__": {"isAdmin": True},
                            "evil": generate_malicious_string(),
                        },
                        {
                            "maliciousExtension": {
                                "payload": generate_malicious_string(),
                                "injection": random.choice(SQL_INJECTION),
                                "xss": random.choice(XSS_PAYLOADS),
                            }
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
        "evil": generate_malicious_string(),
    }

    for key, value in malicious_extras.items():
        if random.random() < 0.3:  # 30% chance to add each
            base_request[key] = value

    return base_request


def fuzz_progress_notification() -> Dict[str, Any]:
    """Fuzz ProgressNotification with edge cases."""
    # Generate AGGRESSIVE progress tokens to break things
    progress_token_options = [
        generate_malicious_value(),
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
            "progress": generate_malicious_value(),
            "total": generate_malicious_value(),
        },
    }


def fuzz_cancel_notification() -> Dict[str, Any]:
    """Fuzz CancelNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {
            "requestId": generate_malicious_value(),
            "reason": generate_malicious_string(),
        },
    }


def fuzz_list_resources_request() -> Dict[str, Any]:
    """Fuzz ListResourcesRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "resources/list",
        "params": {
            "cursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
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
        "id": generate_malicious_value(),
        "method": "resources/read",
        "params": {
            "uri": random.choice(malicious_uris + [generate_malicious_string()])
        },
    }


def fuzz_set_level_request() -> Dict[str, Any]:
    """Fuzz SetLevelRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "logging/setLevel",
        "params": {"level": generate_malicious_value()},
    }


def fuzz_generic_jsonrpc_request() -> Dict[str, Any]:
    """Fuzz generic JSON-RPC requests with edge cases."""
    return {
        "jsonrpc": random.choice(["2.0", "1.0", "3.0", "invalid", "", None]),
        "id": generate_malicious_value(),
        "method": generate_malicious_string(),
        "params": generate_malicious_value(),
    }


def fuzz_call_tool_result() -> Dict[str, Any]:
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


def fuzz_sampling_message() -> Dict[str, Any]:
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


def fuzz_create_message_request() -> Dict[str, Any]:
    """Fuzz CreateMessageRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "sampling/createMessage",
        "params": {
            "messages": [fuzz_sampling_message() for _ in range(random.randint(0, 5))],
            "modelPreferences": generate_malicious_value(),
            "systemPrompt": generate_malicious_string(),
            "includeContext": generate_malicious_string(),
            "temperature": generate_malicious_value(),
            "maxTokens": generate_malicious_value(),
            "stopSequences": generate_malicious_value(),
            "metadata": generate_malicious_value(),
        },
    }


def fuzz_list_prompts_request() -> Dict[str, Any]:
    """Fuzz ListPromptsRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "prompts/list",
        "params": {
            "cursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_get_prompt_request() -> Dict[str, Any]:
    """Fuzz GetPromptRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "prompts/get",
        "params": {
            "name": generate_malicious_string(),
            "arguments": generate_malicious_value(),
        },
    }


def fuzz_list_roots_request() -> Dict[str, Any]:
    """Fuzz ListRootsRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "roots/list",
        "params": {"_meta": generate_malicious_value()},
    }


def fuzz_subscribe_request() -> Dict[str, Any]:
    """Fuzz SubscribeRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "resources/subscribe",
        "params": {"uri": generate_malicious_string()},
    }


def fuzz_unsubscribe_request() -> Dict[str, Any]:
    """Fuzz UnsubscribeRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "resources/unsubscribe",
        "params": {"uri": generate_malicious_string()},
    }


def fuzz_complete_request() -> Dict[str, Any]:
    """Fuzz CompleteRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "completion/complete",
        "params": {
            "ref": generate_malicious_value(),
            "argument": generate_malicious_value(),
        },
    }


def fuzz_list_resource_templates_request() -> Dict[str, Any]:
    """Fuzz ListResourceTemplatesRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "resources/templates/list",
        "params": {
            "cursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_elicit_request() -> Dict[str, Any]:
    """Fuzz ElicitRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "elicitation/create",
        "params": {
            "message": generate_malicious_string(),
            "requestedSchema": generate_malicious_value(),
        },
    }


def fuzz_ping_request() -> Dict[str, Any]:
    """Fuzz PingRequest with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "method": "ping",
        "params": generate_malicious_value(),
    }


# Result schemas for fuzzing
def fuzz_initialize_result() -> Dict[str, Any]:
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


def fuzz_list_resources_result() -> Dict[str, Any]:
    """Fuzz ListResourcesResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "resources": [
                generate_malicious_value()
                for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_resource_templates_result() -> Dict[str, Any]:
    """Fuzz ListResourceTemplatesResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "resourceTemplates": [
                generate_malicious_value()
                for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_read_resource_result() -> Dict[str, Any]:
    """Fuzz ReadResourceResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "contents": [
                generate_malicious_value()
                for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_prompts_result() -> Dict[str, Any]:
    """Fuzz ListPromptsResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "prompts": [
                generate_malicious_value()
                for _ in range(random.randint(0, 10))
            ],
            "nextCursor": generate_malicious_string(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_get_prompt_result() -> Dict[str, Any]:
    """Fuzz GetPromptResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "description": generate_malicious_string(),
            "messages": [
                generate_malicious_value()
                for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_list_tools_result() -> Dict[str, Any]:
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


def fuzz_complete_result() -> Dict[str, Any]:
    """Fuzz CompleteResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "completion": {
                "values": [
                    generate_malicious_string()
                    for _ in range(random.randint(0, 5))
                ],
                "total": generate_malicious_value(),
                "hasMore": generate_malicious_value(),
            },
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_create_message_result() -> Dict[str, Any]:
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


def fuzz_list_roots_result() -> Dict[str, Any]:
    """Fuzz ListRootsResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "roots": [generate_malicious_value() for _ in range(random.randint(0, 5))],
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_ping_result() -> Dict[str, Any]:
    """Fuzz PingResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": generate_malicious_value(),
    }


def fuzz_elicit_result() -> Dict[str, Any]:
    """Fuzz ElicitResult with edge cases."""
    return {
        "jsonrpc": "2.0",
        "id": generate_malicious_value(),
        "result": {
            "content": [
                generate_malicious_value()
                for _ in range(random.randint(0, 5))
            ],
            "_meta": generate_malicious_value(),
        },
    }


# Notification schemas for fuzzing
def fuzz_logging_message_notification() -> Dict[str, Any]:
    """Fuzz LoggingMessageNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/message",
        "params": {
            "level": generate_malicious_value(),
            "logger": generate_malicious_string(),
            "data": generate_malicious_value(),
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_resource_list_changed_notification() -> Dict[str, Any]:
    """Fuzz ResourceListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/resources/list_changed",
        "params": {
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_resource_updated_notification() -> Dict[str, Any]:
    """Fuzz ResourceUpdatedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated",
        "params": {
            "uri": generate_malicious_string(),
        },
    }


def fuzz_prompt_list_changed_notification() -> Dict[str, Any]:
    """Fuzz PromptListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/prompts/list_changed",
        "params": {
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_tool_list_changed_notification() -> Dict[str, Any]:
    """Fuzz ToolListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed",
        "params": {
            "_meta": generate_malicious_value(),
        },
    }


def fuzz_roots_list_changed_notification() -> Dict[str, Any]:
    """Fuzz RootsListChangedNotification with edge cases."""
    return {
        "jsonrpc": "2.0",
        "method": "notifications/roots/list_changed",
        "params": {
            "_meta": generate_malicious_value(),
        },
    }


# Content block schemas for fuzzing
def fuzz_text_content() -> Dict[str, Any]:
    """Fuzz TextContent with edge cases."""
    return {
        "type": "text",
        "text": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_image_content() -> Dict[str, Any]:
    """Fuzz ImageContent with edge cases."""
    return {
        "type": "image",
        "data": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


def fuzz_audio_content() -> Dict[str, Any]:
    """Fuzz AudioContent with edge cases."""
    return {
        "type": "audio",
        "data": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "_meta": generate_malicious_value(),
        "annotations": generate_malicious_value(),
    }


# Resource schemas for fuzzing
def fuzz_resource() -> Dict[str, Any]:
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


def fuzz_resource_template() -> Dict[str, Any]:
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


def fuzz_text_resource_contents() -> Dict[str, Any]:
    """Fuzz TextResourceContents with edge cases."""
    return {
        "uri": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "text": generate_malicious_string(),
        "_meta": generate_malicious_value(),
    }


def fuzz_blob_resource_contents() -> Dict[str, Any]:
    """Fuzz BlobResourceContents with edge cases."""
    return {
        "uri": generate_malicious_string(),
        "mimeType": generate_malicious_string(),
        "blob": generate_malicious_string(),
        "_meta": generate_malicious_value(),
    }


# Tool schemas for fuzzing
def fuzz_tool() -> Dict[str, Any]:
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
