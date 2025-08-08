#!/usr/bin/env python3
"""
Protocol Fuzzing Strategies

This module contains Hypothesis strategies for generating fuzz data
for MCP protocol types.
"""

import random
import string
from typing import Any, Dict

# MCP Protocol constants
LATEST_PROTOCOL_VERSION = "2024-11-05"
JSONRPC_VERSION = "2.0"

# Logging levels
LOGGING_LEVELS = [
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
]

# Roles
ROLES = ["user", "assistant"]

# Special characters and edge cases for aggressive fuzzing
SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\"
UNICODE_CHARS = "🚀🔥💯🎯⚡🌟💎🎪🎭🎨🎬🎤🎧🎼🎹🎸🎻🎺🎷🥁"
NULL_BYTES = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
ESCAPE_CHARS = "\\n\\t\\r\\b\\f\\v\\a"
HTML_ENTITIES = "&lt;&gt;&amp;&quot;&apos;&nbsp;&copy;&reg;&trade;"
SQL_INJECTION = (
    "' OR 1=1; --",
    "'; DROP TABLE users; --",
    "1' UNION SELECT * FROM users --",
)
XSS_PAYLOADS = (
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
)
PATH_TRAVERSAL = "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam"
OVERFLOW_VALUES = ["A" * 10000, "0" * 10000, "💯" * 1000, "🚀" * 1000]


class ProtocolStrategies:
    """Hypothesis strategies for protocol type fuzzing."""

    @staticmethod
    def _generate_random_text(min_size: int = 1, max_size: int = 50) -> str:
        """Generate random text with extensive edge cases."""
        length = random.randint(min_size, max_size)

        # Choose from various text generation strategies
        strategy = random.choice(
            [
                "normal",
                "special_chars",
                "unicode",
                "null_bytes",
                "escape_chars",
                "html_entities",
                "sql_injection",
                "xss",
                "path_traversal",
                "overflow",
            ]
        )

        if strategy == "normal":
            chars = string.ascii_letters + string.digits
            return "".join(random.choice(chars) for _ in range(length))
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
        else:
            return "".join(random.choice(string.printable) for _ in range(length))

    @staticmethod
    def _generate_random_integer(
        min_value: int = -1000000, max_value: int = 1000000
    ) -> int:
        """Generate random integer with extreme values and edge cases."""
        # Choose from various integer generation strategies
        strategy = random.choice(
            ["normal", "extreme", "zero", "negative", "overflow", "special"]
        )

        if strategy == "normal":
            return random.randint(min_value, max_value)
        elif strategy == "extreme":
            extreme_values = [
                -2147483648,
                2147483647,
                -9223372036854775808,
                9223372036854775807,
                0,
                1,
                -1,
            ]
            return random.choice(extreme_values)
        elif strategy == "zero":
            return 0
        elif strategy == "negative":
            return random.randint(-1000000, -1)
        elif strategy == "overflow":
            overflow_values = [2**31, 2**63, -(2**31), -(2**63), 2**64, -(2**64)]
            return random.choice(overflow_values)
        elif strategy == "special":
            special_values = [None, float("inf"), float("-inf"), float("nan")]
            return (
                random.choice(special_values)
                if random.choice([True, False])
                else random.randint(min_value, max_value)
            )
        else:
            return random.randint(min_value, max_value)

    @staticmethod
    def _generate_random_float(
        min_value: float = -1000000.0, max_value: float = 1000000.0
    ) -> float:
        """Generate random float with extreme values and edge cases."""
        strategy = random.choice(
            ["normal", "extreme", "zero", "negative", "infinity", "nan", "special"]
        )

        if strategy == "normal":
            return random.uniform(min_value, max_value)
        elif strategy == "extreme":
            extreme_values = [
                float("inf"),
                float("-inf"),
                1e308,
                -1e308,
                1e-308,
                -1e-308,
            ]
            return random.choice(extreme_values)
        elif strategy == "zero":
            return 0.0
        elif strategy == "negative":
            return random.uniform(-1000000.0, -0.1)
        elif strategy == "infinity":
            return random.choice([float("inf"), float("-inf")])
        elif strategy == "nan":
            return float("nan")
        elif strategy == "special":
            special_values = [None, "not_a_number", "infinity"]
            return (
                random.choice(special_values)
                if random.choice([True, False])
                else random.uniform(min_value, max_value)
            )
        else:
            return random.uniform(min_value, max_value)

    @staticmethod
    def _generate_random_boolean() -> bool:
        """Generate random boolean with edge cases."""
        # Sometimes return non-boolean values for fuzzing
        if random.random() < 0.1:  # 10% chance for edge cases
            return random.choice(
                [None, 0, 1, "true", "false", "True", "False", "", "yes", "no"]
            )
        return random.choice([True, False])

    @staticmethod
    def _generate_random_list(
        item_generator, min_size: int = 1, max_size: int = 10
    ) -> list:
        """Generate random list with edge cases."""
        strategy = random.choice(
            ["normal", "empty", "large", "mixed", "nested", "special"]
        )

        if strategy == "normal":
            length = random.randint(min_size, max_size)
            return [item_generator() for _ in range(length)]
        elif strategy == "empty":
            return []
        elif strategy == "large":
            length = random.randint(100, 1000)
            return [item_generator() for _ in range(length)]
        elif strategy == "mixed":
            length = random.randint(min_size, max_size)
            return [
                item_generator() if random.random() < 0.7 else None
                for _ in range(length)
            ]
        elif strategy == "nested":
            length = random.randint(min_size, max_size)
            return [
                [item_generator() for _ in range(random.randint(1, 3))]
                for _ in range(length)
            ]
        elif strategy == "special":
            return [None, "", 0, False, [], {}, "special_value"]
        else:
            length = random.randint(min_size, max_size)
            return [item_generator() for _ in range(length)]

    @staticmethod
    def _generate_random_object() -> Dict[str, Any]:
        """Generate random object with edge cases."""
        strategy = random.choice(
            ["normal", "empty", "large", "nested", "special_keys", "special_values"]
        )

        if strategy == "normal":
            num_keys = random.randint(1, 5)
            obj = {}
            for _ in range(num_keys):
                key = ProtocolStrategies._generate_random_text(1, 10)
                value = ProtocolStrategies._generate_random_text(1, 20)
                obj[key] = value
            return obj
        elif strategy == "empty":
            return {}
        elif strategy == "large":
            num_keys = random.randint(50, 200)
            obj = {}
            for _ in range(num_keys):
                key = ProtocolStrategies._generate_random_text(1, 20)
                value = ProtocolStrategies._generate_random_text(1, 100)
                obj[key] = value
            return obj
        elif strategy == "nested":
            return {
                "level1": {
                    "level2": {
                        "level3": ProtocolStrategies._generate_random_text(1, 20)
                    }
                }
            }
        elif strategy == "special_keys":
            return {
                "": ProtocolStrategies._generate_random_text(),
                "null": None,
                "special!@#": ProtocolStrategies._generate_random_text(),
                "unicode🚀": ProtocolStrategies._generate_random_text(),
                "very_long_key_"
                + "a" * 100: ProtocolStrategies._generate_random_text(),
            }
        elif strategy == "special_values":
            return {
                "null_value": None,
                "empty_string": "",
                "zero": 0,
                "false": False,
                "empty_list": [],
                "empty_object": {},
                "special_chars": "!@#$%^&*()",
                "unicode": "🚀🔥💯",
                "sql_injection": random.choice(SQL_INJECTION),
                "xss": random.choice(XSS_PAYLOADS),
            }
        else:
            return {"default": ProtocolStrategies._generate_random_text()}

    @staticmethod
    def fuzz_initialize_request() -> Dict[str, Any]:
        """Fuzz InitializeRequest with aggressive edge cases."""
        # Generate random protocol version with extensive edge cases
        protocol_versions = [
            LATEST_PROTOCOL_VERSION,
            ProtocolStrategies._generate_random_text(1, 200),
            ProtocolStrategies._generate_random_text(0, 1000),
            "",
            "invalid-version",
            "2024-11-05-invalid",
            "2024-11-05-extra-stuff",
            "🚀🔥💯",  # Unicode version
            "!@#$%^&*()",  # Special chars version
            "' OR 1=1; --",  # SQL injection
            "<script>alert('xss')</script>",  # XSS payload
            "../../../etc/passwd",  # Path traversal
            "A" * 10000,  # Overflow
            None,  # Null version
            random.choice([0, 1, True, False, [], {}]),  # Invalid types
        ]

        # Generate random capabilities with aggressive fuzzing
        capabilities_options = [
            {
                "experimental": {ProtocolStrategies._generate_random_text(): {}},
                "roots": {"listChanged": ProtocolStrategies._generate_random_boolean()},
                "sampling": {},
            },
            {},  # Empty capabilities
            {"invalid_capability": ProtocolStrategies._generate_random_text()},
            {
                "experimental": {
                    ProtocolStrategies._generate_random_text(): (
                        ProtocolStrategies._generate_random_text()
                    )
                }
            },
            {
                "🚀🔥💯": {"unicode_key": "unicode_value"},
                "!@#$%^&*()": {"special_chars": "special_value"},
                "sql_injection": {"' OR 1=1; --": "malicious_value"},
                "xss": {"<script>alert('xss')</script>": "xss_value"},
                "very_long_key_" + "a" * 500: {"overflow": "overflow_value"},
            },
            None,  # Null capabilities
            "invalid_capabilities_type",  # Wrong type
            [1, 2, 3, 4, 5],  # Array instead of object
            ProtocolStrategies._generate_random_text(
                1, 1000
            ),  # String instead of object
        ]

        # Generate random client info with aggressive fuzzing
        client_info_options = [
            {
                "name": ProtocolStrategies._generate_random_text(1, 200),
                "version": ProtocolStrategies._generate_random_text(1, 100),
            },
            {
                "name": ProtocolStrategies._generate_random_text(0, 1000),
                "version": ProtocolStrategies._generate_random_text(0, 1000),
            },
            {"name": "", "version": ""},
            {"invalid_field": ProtocolStrategies._generate_random_text()},
            {
                "🚀🔥💯": "unicode_name",
                "!@#$%^&*()": "special_chars_name",
                "sql_injection": "' OR 1=1; --",
                "xss": "<script>alert('xss')</script>",
                "path_traversal": "../../../etc/passwd",
                "overflow": "A" * 10000,
            },
            None,  # Null client info
            "invalid_client_info_type",  # Wrong type
            [1, 2, 3, 4, 5],  # Array instead of object
            ProtocolStrategies._generate_random_text(
                1, 1000
            ),  # String instead of object
        ]

        # Generate random JSON-RPC version
        jsonrpc_versions = [
            JSONRPC_VERSION,
            "1.0",
            "3.0",
            "invalid",
            "",
            None,
            ProtocolStrategies._generate_random_text(1, 50),
            "🚀🔥💯",
            "!@#$%^&*()",
        ]

        # Generate random ID with aggressive fuzzing
        id_options = [
            ProtocolStrategies._generate_random_integer(),
            ProtocolStrategies._generate_random_text(),
            None,
            "",
            ProtocolStrategies._generate_random_integer(-1000000, 1000000),
            ProtocolStrategies._generate_random_text(0, 1000),
            float("inf"),
            float("nan"),
            "🚀🔥💯",
            "!@#$%^&*()",
            "' OR 1=1; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "A" * 10000,
        ]

        return {
            "jsonrpc": random.choice(jsonrpc_versions),
            "id": random.choice(id_options),
            "method": random.choice(
                [
                    "initialize",
                    "INITIALIZE",
                    "Initialize",
                    "🚀🔥💯",
                    "!@#$%^&*()",
                    "' OR 1=1; --",
                    "<script>alert('xss')</script>",
                    "../../../etc/passwd",
                    "A" * 10000,
                    "",
                    None,
                ]
            ),
            "params": {
                "protocolVersion": random.choice(protocol_versions),
                "capabilities": random.choice(capabilities_options),
                "clientInfo": random.choice(client_info_options),
            },
        }

    @staticmethod
    def fuzz_progress_notification() -> Dict[str, Any]:
        """Fuzz ProgressNotification with edge cases."""
        # Generate random progress token
        progress_token_options = [
            ProtocolStrategies._generate_random_integer(),
            ProtocolStrategies._generate_random_text(),
            "",
            None,
            ProtocolStrategies._generate_random_integer(-1000, 1000),
            ProtocolStrategies._generate_random_text(0, 1000),
        ]

        # Generate random progress value
        progress_options = [
            ProtocolStrategies._generate_random_integer(0, 1000),
            ProtocolStrategies._generate_random_integer(-1000, -1),
            ProtocolStrategies._generate_random_integer(1000000, 9999999),
            float("nan") if random.choice([True, False]) else float("inf"),
            0,
            None,
        ]

        # Generate random total value
        total_options = [
            ProtocolStrategies._generate_random_integer(1, 10000),
            ProtocolStrategies._generate_random_integer(-1000, -1),
            ProtocolStrategies._generate_random_integer(1000000, 9999999),
            float("nan") if random.choice([True, False]) else float("inf"),
            None,
            0,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "method": "notifications/progress",
            "params": {
                "progressToken": random.choice(progress_token_options),
                "progress": random.choice(progress_options),
                "total": random.choice(total_options),
            },
        }

    @staticmethod
    def fuzz_cancel_notification() -> Dict[str, Any]:
        """Fuzz CancelNotification with edge cases."""
        # Generate random request ID
        request_id_options = [
            ProtocolStrategies._generate_random_integer(),
            ProtocolStrategies._generate_random_text(),
            "",
            None,
            "unknown-request-id",
            "already-completed-id",
            ProtocolStrategies._generate_random_text(0, 1000),
        ]

        # Generate random reason
        reason_options = [
            ProtocolStrategies._generate_random_text(0, 200),
            "",
            None,
            ProtocolStrategies._generate_random_text(0, 10000),
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "method": "notifications/cancelled",
            "params": {
                "requestId": random.choice(request_id_options),
                "reason": random.choice(reason_options),
            },
        }

    @staticmethod
    def fuzz_list_resources_request() -> Dict[str, Any]:
        """Fuzz ListResourcesRequest with edge cases."""
        # Generate random cursor
        cursor_options = [
            ProtocolStrategies._generate_random_text(0, 100),
            "",
            None,
            ProtocolStrategies._generate_random_text(0, 10000),
            "invalid-cursor",
            "cursor-with-special-chars-!@#$%^&*()",
        ]

        # Generate random meta
        meta_options = [
            {
                "progressToken": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                )
            },
            {},
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "resources/list",
            "params": {
                "cursor": random.choice(cursor_options),
                "_meta": random.choice(meta_options),
            },
        }

    @staticmethod
    def fuzz_read_resource_request() -> Dict[str, Any]:
        """Fuzz ReadResourceRequest with edge cases."""
        # Generate random URI
        uri_options = [
            "file:///path/to/resource",
            "http://example.com/resource",
            "https://example.com/resource",
            "ftp://example.com/resource",
            "invalid://uri",
            "",
            "not-a-uri",
            "file:///path/with/spaces and special chars!@#",
            "file:///path/with/unicode/测试",
            "file:///path/with/very/long/path/" + "a" * 1000,
            "file:///path/with/../relative/path",
            "file:///path/with/../../../../../etc/passwd",
            "data:text/plain;base64,SGVsbG8gV29ybGQ=",
            "data:application/json,{}",
            'data:application/json,{"invalid":json}',
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "resources/read",
            "params": {"uri": random.choice(uri_options)},
        }

    @staticmethod
    def fuzz_set_level_request() -> Dict[str, Any]:
        """Fuzz SetLevelRequest with edge cases."""
        # Generate random level
        level_options = [
            random.choice(LOGGING_LEVELS),  # Valid levels
            ProtocolStrategies._generate_random_text(0, 20),  # Invalid levels
            "",
            "INVALID_LEVEL",
            "DEBUG",
            "debug",
            "Debug",
            "level-with-spaces",
            "level-with-special-chars!@#",
            "very-long-level-name-that-exceeds-normal-bounds",
            ProtocolStrategies._generate_random_integer(),  # Numeric levels
            ProtocolStrategies._generate_random_float(),  # Float levels
            ProtocolStrategies._generate_random_boolean(),  # Boolean levels
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "logging/setLevel",
            "params": {"level": random.choice(level_options)},
        }

    @staticmethod
    def fuzz_generic_jsonrpc_request() -> Dict[str, Any]:
        """Fuzz generic JSON-RPC requests with edge cases."""
        # Define different request types with more variation in jsonrpc field
        request_types = [
            # Valid request with standard jsonrpc
            {
                "jsonrpc": JSONRPC_VERSION,
                "id": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                ),
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": random.choice(
                    [
                        {},
                        {
                            ProtocolStrategies._generate_random_text(): (
                                ProtocolStrategies._generate_random_text()
                            )
                        },
                    ]
                ),
            },
            # Missing jsonrpc
            {
                "id": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                ),
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": {},
            },
            # Invalid jsonrpc version
            {
                "jsonrpc": random.choice(
                    ["1.0", "3.0", "invalid", "", None, "2.1", "1.9", "2.0.1"]
                ),
                "id": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                ),
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": {},
            },
            # Missing id
            {
                "jsonrpc": JSONRPC_VERSION,
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": {},
            },
            # Invalid id
            {
                "jsonrpc": JSONRPC_VERSION,
                "id": random.choice(
                    [None, "", [], {}, ProtocolStrategies._generate_random_float()]
                ),
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": {},
            },
            # Request with different jsonrpc versions
            {
                "jsonrpc": random.choice(["2.0", "1.0", "3.0", "2.1", "1.9"]),
                "id": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                ),
                "method": ProtocolStrategies._generate_random_text(1, 50),
                "params": {},
            },
        ]

        return random.choice(request_types)

    @staticmethod
    def fuzz_call_tool_result() -> Dict[str, Any]:
        """Fuzz CallToolResult with edge cases."""
        # Generate random content
        content_options = [
            [
                {
                    "type": "text",
                    "text": ProtocolStrategies._generate_random_text(0, 1000),
                }
            ],
            [
                {
                    "type": "image",
                    "data": ProtocolStrategies._generate_random_text(0, 1000),
                    "mimeType": ProtocolStrategies._generate_random_text(0, 100),
                }
            ],
            [
                {
                    "type": "resource",
                    "resource": {
                        "uri": ProtocolStrategies._generate_random_text(0, 1000),
                        "text": ProtocolStrategies._generate_random_text(0, 1000),
                    },
                }
            ],
            [
                {
                    "type": ProtocolStrategies._generate_random_text(0, 20),
                    "invalid_field": ProtocolStrategies._generate_random_text(),
                }
            ],
        ]

        # Generate random isError
        is_error_options = [
            ProtocolStrategies._generate_random_boolean(),
            None,
            ProtocolStrategies._generate_random_integer(),
            ProtocolStrategies._generate_random_text(),
        ]

        # Generate random meta
        meta_options = [
            {"metadata": ProtocolStrategies._generate_random_text()},
            {},
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "result": {
                "content": random.choice(content_options),
                "isError": random.choice(is_error_options),
                "_meta": random.choice(meta_options),
            },
        }

    @staticmethod
    def fuzz_sampling_message() -> Dict[str, Any]:
        """Fuzz SamplingMessage with edge cases."""
        # Generate random role
        role_options = [
            random.choice(ROLES),
            ProtocolStrategies._generate_random_text(0, 20),
            "",
            "INVALID_ROLE",
            "system",
            "function",
            "role-with-spaces",
            "role-with-special-chars!@#",
            ProtocolStrategies._generate_random_integer(),
            ProtocolStrategies._generate_random_float(),
            ProtocolStrategies._generate_random_boolean(),
            None,
        ]

        # Generate random content
        content_options = [
            [
                {
                    "type": "text",
                    "text": ProtocolStrategies._generate_random_text(0, 10000),
                }
            ],
            [
                {
                    "type": "image",
                    "data": ProtocolStrategies._generate_random_text(0, 100000),
                    "mimeType": ProtocolStrategies._generate_random_text(0, 100),
                }
            ],
            [
                {
                    "type": ProtocolStrategies._generate_random_text(0, 20),
                    "invalid_content": ProtocolStrategies._generate_random_text(),
                }
            ],
        ]

        return {
            "role": random.choice(role_options),
            "content": random.choice(content_options),
        }

    @staticmethod
    def fuzz_create_message_request() -> Dict[str, Any]:
        """Fuzz CreateMessageRequest with edge cases."""
        # Generate random messages
        messages = []
        num_messages = random.randint(0, 100)
        for _ in range(num_messages):
            messages.append(
                {
                    "role": random.choice(ROLES),
                    "content": [
                        {
                            "type": "text",
                            "text": ProtocolStrategies._generate_random_text(0, 10000),
                        }
                    ],
                }
            )

        # Generate random model preferences
        model_preferences_options = [
            {
                "hints": [
                    {"name": ProtocolStrategies._generate_random_text(0, 100)}
                    for _ in range(random.randint(1, 5))
                ],
                "costPriority": ProtocolStrategies._generate_random_float(0.0, 1.0),
                "speedPriority": ProtocolStrategies._generate_random_float(0.0, 1.0),
                "intelligencePriority": ProtocolStrategies._generate_random_float(
                    0.0, 1.0
                ),
            },
            {},
            None,
        ]

        # Generate random system prompt
        system_prompt_options = [
            ProtocolStrategies._generate_random_text(0, 10000),
            "",
            None,
        ]

        # Generate random include context
        include_context_options = [
            random.choice(["none", "thisServer", "allServers"]),
            ProtocolStrategies._generate_random_text(0, 20),
            "",
            None,
        ]

        # Generate random temperature
        temperature_options = [
            ProtocolStrategies._generate_random_float(0.0, 2.0),
            ProtocolStrategies._generate_random_float(-1.0, 0.0),
            ProtocolStrategies._generate_random_float(2.1, 10.0),
            None,
        ]

        # Generate random max tokens
        max_tokens_options = [
            ProtocolStrategies._generate_random_integer(1, 10000),
            ProtocolStrategies._generate_random_integer(-1000, 0),
            ProtocolStrategies._generate_random_integer(10001, 100000),
            0,
            None,
        ]

        # Generate random stop sequences
        stop_sequences_options = [
            [
                ProtocolStrategies._generate_random_text(0, 100)
                for _ in range(random.randint(1, 5))
            ],
            [
                ProtocolStrategies._generate_random_text(0, 1000)
                for _ in range(random.randint(1, 5))
            ],
            [],
            None,
        ]

        # Generate random metadata
        metadata_options = [
            {
                ProtocolStrategies._generate_random_text(): (
                    ProtocolStrategies._generate_random_text()
                )
                for _ in range(random.randint(1, 5))
            },
            {},
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "sampling/createMessage",
            "params": {
                "messages": messages,
                "modelPreferences": random.choice(model_preferences_options),
                "systemPrompt": random.choice(system_prompt_options),
                "includeContext": random.choice(include_context_options),
                "temperature": random.choice(temperature_options),
                "maxTokens": random.choice(max_tokens_options),
                "stopSequences": random.choice(stop_sequences_options),
                "metadata": random.choice(metadata_options),
            },
        }

    @staticmethod
    def fuzz_list_prompts_request() -> Dict[str, Any]:
        """Fuzz ListPromptsRequest with edge cases."""
        # Generate random cursor
        cursor_options = [
            ProtocolStrategies._generate_random_text(0, 100),
            "",
            None,
            ProtocolStrategies._generate_random_text(0, 10000),
        ]

        # Generate random meta
        meta_options = [
            {
                "progressToken": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                )
            },
            {},
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "prompts/list",
            "params": {
                "cursor": random.choice(cursor_options),
                "_meta": random.choice(meta_options),
            },
        }

    @staticmethod
    def fuzz_get_prompt_request() -> Dict[str, Any]:
        """Fuzz GetPromptRequest with edge cases."""
        # Generate random name
        name_options = [
            ProtocolStrategies._generate_random_text(1, 100),
            "",
            "invalid-prompt-name",
            "prompt-with-spaces and special chars!@#",
            "prompt-with-unicode-测试",
            ProtocolStrategies._generate_random_text(0, 1000),
        ]

        # Generate random arguments
        arguments_options = [
            {
                ProtocolStrategies._generate_random_text(): (
                    ProtocolStrategies._generate_random_text()
                )
                for _ in range(random.randint(1, 5))
            },
            {},
            None,
            {
                ProtocolStrategies._generate_random_text(): random.choice(
                    [
                        ProtocolStrategies._generate_random_text(),
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_boolean(),
                    ]
                )
                for _ in range(random.randint(1, 5))
            },
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "prompts/get",
            "params": {
                "name": random.choice(name_options),
                "arguments": random.choice(arguments_options),
            },
        }

    @staticmethod
    def fuzz_list_roots_request() -> Dict[str, Any]:
        """Fuzz ListRootsRequest with edge cases."""
        # Generate random meta
        meta_options = [
            {
                "progressToken": random.choice(
                    [
                        ProtocolStrategies._generate_random_integer(),
                        ProtocolStrategies._generate_random_text(),
                    ]
                )
            },
            {},
            None,
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "roots/list",
            "params": {"_meta": random.choice(meta_options)},
        }

    @staticmethod
    def fuzz_subscribe_request() -> Dict[str, Any]:
        """Fuzz SubscribeRequest with edge cases."""
        # Generate random URI
        uri_options = [
            "file:///path/to/resource",
            "http://example.com/resource",
            "https://example.com/resource",
            "invalid://uri",
            "",
            "not-a-uri",
            "file:///path/with/spaces and special chars!@#",
            "file:///path/with/unicode/测试",
            "file:///path/with/very/long/path/" + "a" * 1000,
            "file:///path/with/../relative/path",
            "file:///path/with/../../../../../etc/passwd",
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "resources/subscribe",
            "params": {"uri": random.choice(uri_options)},
        }

    @staticmethod
    def fuzz_unsubscribe_request() -> Dict[str, Any]:
        """Fuzz UnsubscribeRequest with edge cases."""
        # Generate random URI
        uri_options = [
            "file:///path/to/resource",
            "http://example.com/resource",
            "https://example.com/resource",
            "invalid://uri",
            "",
            "not-a-uri",
            "file:///path/with/spaces and special chars!@#",
            "file:///path/with/unicode/测试",
            "file:///path/with/very/long/path/" + "a" * 1000,
            "file:///path/with/../relative/path",
            "file:///path/with/../../../../../etc/passwd",
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "resources/unsubscribe",
            "params": {"uri": random.choice(uri_options)},
        }

    @staticmethod
    def fuzz_complete_request() -> Dict[str, Any]:
        """Fuzz CompleteRequest with edge cases."""
        # Generate random ref
        ref_options = [
            {
                "type": "ref/resource",
                "uri": ProtocolStrategies._generate_random_text(0, 1000),
            },
            {
                "type": "ref/prompt",
                "name": ProtocolStrategies._generate_random_text(0, 100),
            },
            {
                "type": ProtocolStrategies._generate_random_text(0, 20),
                "invalid_field": ProtocolStrategies._generate_random_text(),
            },
        ]

        # Generate random argument
        argument_options = [
            {
                "name": ProtocolStrategies._generate_random_text(1, 50),
                "value": ProtocolStrategies._generate_random_text(0, 1000),
            },
            {"name": "", "value": ""},
            {
                "name": ProtocolStrategies._generate_random_text(0, 1000),
                "value": ProtocolStrategies._generate_random_text(0, 10000),
            },
        ]

        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": random.choice(
                [
                    ProtocolStrategies._generate_random_integer(),
                    ProtocolStrategies._generate_random_text(),
                ]
            ),
            "method": "completion/complete",
            "params": {
                "ref": random.choice(ref_options),
                "argument": random.choice(argument_options),
            },
        }

    @staticmethod
    def get_protocol_fuzzer_method(protocol_type: str):
        """Get the fuzzer method for a specific protocol type."""
        fuzzer_methods = {
            "InitializeRequest": ProtocolStrategies.fuzz_initialize_request,
            "ProgressNotification": ProtocolStrategies.fuzz_progress_notification,
            "CancelNotification": ProtocolStrategies.fuzz_cancel_notification,
            "ListResourcesRequest": ProtocolStrategies.fuzz_list_resources_request,
            "ReadResourceRequest": ProtocolStrategies.fuzz_read_resource_request,
            "SetLevelRequest": ProtocolStrategies.fuzz_set_level_request,
            "GenericJSONRPCRequest": ProtocolStrategies.fuzz_generic_jsonrpc_request,
            "CallToolResult": ProtocolStrategies.fuzz_call_tool_result,
            "SamplingMessage": ProtocolStrategies.fuzz_sampling_message,
            "CreateMessageRequest": ProtocolStrategies.fuzz_create_message_request,
            "ListPromptsRequest": ProtocolStrategies.fuzz_list_prompts_request,
            "GetPromptRequest": ProtocolStrategies.fuzz_get_prompt_request,
            "ListRootsRequest": ProtocolStrategies.fuzz_list_roots_request,
            "SubscribeRequest": ProtocolStrategies.fuzz_subscribe_request,
            "UnsubscribeRequest": ProtocolStrategies.fuzz_unsubscribe_request,
            "CompleteRequest": ProtocolStrategies.fuzz_complete_request,
        }

        return fuzzer_methods.get(protocol_type)
