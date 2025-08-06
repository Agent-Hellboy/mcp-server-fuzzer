#!/usr/bin/env python3
"""
Protocol Fuzzing Strategies

This module contains Hypothesis strategies for generating fuzz data for MCP protocol types.
"""

from typing import Any, Dict

from hypothesis import strategies as st

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


class ProtocolStrategies:
    """Hypothesis strategies for protocol type fuzzing."""

    @staticmethod
    def fuzz_initialize_request() -> Dict[str, Any]:
        """Fuzz InitializeRequest with various edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("initialize"),
                "params": st.fixed_dictionaries(
                    {
                        "protocolVersion": st.one_of(
                            st.just(LATEST_PROTOCOL_VERSION),
                            st.text(min_size=1, max_size=50),  # Valid versions
                            st.text(min_size=0, max_size=100),  # Invalid versions
                            st.just(""),  # Empty version
                            st.just("invalid-version"),
                            st.just("2024-11-05-invalid"),
                            st.just("2024-11-05-extra-stuff"),
                        ),
                        "capabilities": st.one_of(
                            st.fixed_dictionaries(
                                {
                                    "experimental": st.dictionaries(
                                        st.text(), st.fixed_dictionaries({})
                                    ),
                                    "roots": st.fixed_dictionaries(
                                        {"listChanged": st.booleans()}
                                    ),
                                    "sampling": st.fixed_dictionaries({}),
                                }
                            ),
                            st.fixed_dictionaries({}),  # Empty capabilities
                            st.fixed_dictionaries({"invalid_capability": st.text()}),
                            st.fixed_dictionaries(
                                {"experimental": st.dictionaries(st.text(), st.text())}
                            ),
                        ),
                        "clientInfo": st.one_of(
                            st.fixed_dictionaries(
                                {
                                    "name": st.text(min_size=1, max_size=50),
                                    "version": st.text(min_size=1, max_size=20),
                                }
                            ),
                            st.fixed_dictionaries(
                                {
                                    "name": st.text(
                                        min_size=0, max_size=100
                                    ),  # Empty name
                                    "version": st.text(
                                        min_size=0, max_size=100
                                    ),  # Empty version
                                }
                            ),
                            st.fixed_dictionaries(
                                {"name": st.just(""), "version": st.just("")}
                            ),
                            st.fixed_dictionaries({"invalid_field": st.text()}),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_progress_notification() -> Dict[str, Any]:
        """Fuzz ProgressNotification with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "method": st.just("notifications/progress"),
                "params": st.fixed_dictionaries(
                    {
                        "progressToken": st.one_of(
                            st.integers(),
                            st.text(),
                            st.just(""),
                            st.just(None),
                            st.integers(
                                min_value=-1000, max_value=1000
                            ),  # Negative tokens
                            st.text(min_size=0, max_size=1000),  # Very long tokens
                        ),
                        "progress": st.one_of(
                            st.integers(min_value=0, max_value=1000),  # Normal progress
                            st.integers(
                                min_value=-1000, max_value=-1
                            ),  # Negative progress
                            st.integers(
                                min_value=1000000, max_value=9999999
                            ),  # Very large progress
                            st.floats(
                                allow_nan=True, allow_infinity=True
                            ),  # Invalid floats
                            st.just(0),
                            st.just(None),
                        ),
                        "total": st.one_of(
                            st.integers(min_value=1, max_value=10000),
                            st.integers(
                                min_value=-1000, max_value=-1
                            ),  # Negative total
                            st.integers(
                                min_value=1000000, max_value=9999999
                            ),  # Very large total
                            st.floats(allow_nan=True, allow_infinity=True),
                            st.just(None),
                            st.just(0),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_cancel_notification() -> Dict[str, Any]:
        """Fuzz CancelNotification with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "method": st.just("notifications/cancelled"),
                "params": st.fixed_dictionaries(
                    {
                        "requestId": st.one_of(
                            st.integers(),
                            st.text(),
                            st.just(""),
                            st.just(None),
                            st.just("unknown-request-id"),
                            st.just("already-completed-id"),
                            st.text(min_size=0, max_size=1000),  # Very long IDs
                        ),
                        "reason": st.one_of(
                            st.text(min_size=0, max_size=200),
                            st.just(""),
                            st.just(None),
                            st.text(min_size=0, max_size=10000),  # Very long reasons
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_list_resources_request() -> Dict[str, Any]:
        """Fuzz ListResourcesRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("resources/list"),
                "params": st.fixed_dictionaries(
                    {
                        "cursor": st.one_of(
                            st.text(min_size=0, max_size=100),
                            st.just(""),
                            st.just(None),
                            st.text(min_size=0, max_size=10000),  # Very long cursors
                            st.just("invalid-cursor"),
                            st.just("cursor-with-special-chars-!@#$%^&*()"),
                        ),
                        "_meta": st.one_of(
                            st.fixed_dictionaries(
                                {"progressToken": st.one_of(st.integers(), st.text())}
                            ),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_read_resource_request() -> Dict[str, Any]:
        """Fuzz ReadResourceRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("resources/read"),
                "params": st.fixed_dictionaries(
                    {
                        "uri": st.one_of(
                            st.just("file:///path/to/resource"),
                            st.just("http://example.com/resource"),
                            st.just("https://example.com/resource"),
                            st.just("ftp://example.com/resource"),
                            st.just("invalid://uri"),
                            st.just(""),
                            st.just("not-a-uri"),
                            st.just("file:///path/with/spaces and special chars!@#"),
                            st.just("file:///path/with/unicode/测试"),
                            st.just("file:///path/with/very/long/path/" + "a" * 1000),
                            st.just("file:///path/with/../relative/path"),
                            st.just("file:///path/with/../../../../../etc/passwd"),
                            st.just("data:text/plain;base64,SGVsbG8gV29ybGQ="),
                            st.just("data:application/json,{}"),
                            st.just('data:application/json,{"invalid":json}'),
                        )
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_set_level_request() -> Dict[str, Any]:
        """Fuzz SetLevelRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("logging/setLevel"),
                "params": st.fixed_dictionaries(
                    {
                        "level": st.one_of(
                            st.sampled_from(LOGGING_LEVELS),  # Valid levels
                            st.text(min_size=0, max_size=20),  # Invalid levels
                            st.just(""),
                            st.just("INVALID_LEVEL"),
                            st.just("DEBUG"),
                            st.just("debug"),
                            st.just("Debug"),
                            st.just("level-with-spaces"),
                            st.just("level-with-special-chars!@#"),
                            st.just("very-long-level-name-that-exceeds-normal-bounds"),
                            st.integers(),  # Numeric levels
                            st.floats(),  # Float levels
                            st.booleans(),  # Boolean levels
                            st.just(None),
                        )
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_generic_jsonrpc_request() -> Dict[str, Any]:
        """Fuzz generic JSON-RPC requests with edge cases."""
        return st.one_of(
            # Valid request
            st.fixed_dictionaries(
                {
                    "jsonrpc": st.just(JSONRPC_VERSION),
                    "id": st.one_of(st.integers(), st.text()),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.one_of(
                        st.fixed_dictionaries({}), st.dictionaries(st.text(), st.text())
                    ),
                }
            ),
            # Missing jsonrpc
            st.fixed_dictionaries(
                {
                    "id": st.one_of(st.integers(), st.text()),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.fixed_dictionaries({}),
                }
            ),
            # Invalid jsonrpc version
            st.fixed_dictionaries(
                {
                    "jsonrpc": st.one_of(
                        st.just("1.0"),
                        st.just("3.0"),
                        st.just("invalid"),
                        st.just(""),
                        st.just(None),
                    ),
                    "id": st.one_of(st.integers(), st.text()),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.fixed_dictionaries({}),
                }
            ),
            # Missing id
            st.fixed_dictionaries(
                {
                    "jsonrpc": st.just(JSONRPC_VERSION),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.fixed_dictionaries({}),
                }
            ),
            # Invalid id
            st.fixed_dictionaries(
                {
                    "jsonrpc": st.just(JSONRPC_VERSION),
                    "id": st.one_of(
                        st.just(None),
                        st.just(""),
                        st.just([]),
                        st.just({}),
                        st.floats(),
                    ),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.fixed_dictionaries({}),
                }
            ),
            # Deeply nested params
            st.fixed_dictionaries(
                {
                    "jsonrpc": st.just(JSONRPC_VERSION),
                    "id": st.one_of(st.integers(), st.text()),
                    "method": st.text(min_size=1, max_size=50),
                    "params": st.recursive(
                        st.fixed_dictionaries({}),
                        lambda children: st.dictionaries(st.text(), children),
                        max_leaves=10,
                    ),
                }
            ),
        ).example()

    @staticmethod
    def fuzz_call_tool_result() -> Dict[str, Any]:
        """Fuzz CallToolResult with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "result": st.fixed_dictionaries(
                    {
                        "content": st.one_of(
                            st.lists(
                                st.fixed_dictionaries(
                                    {
                                        "type": st.just("text"),
                                        "text": st.text(min_size=0, max_size=1000),
                                    }
                                )
                            ),
                            st.lists(
                                st.fixed_dictionaries(
                                    {
                                        "type": st.just("image"),
                                        "data": st.text(min_size=0, max_size=1000),
                                        "mimeType": st.text(min_size=0, max_size=100),
                                    }
                                )
                            ),
                            st.lists(
                                st.fixed_dictionaries(
                                    {
                                        "type": st.just("resource"),
                                        "resource": st.fixed_dictionaries(
                                            {
                                                "uri": st.text(
                                                    min_size=0, max_size=1000
                                                ),
                                                "text": st.text(
                                                    min_size=0, max_size=1000
                                                ),
                                            }
                                        ),
                                    }
                                )
                            ),
                            st.lists(
                                st.fixed_dictionaries(
                                    {
                                        "type": st.text(min_size=0, max_size=20),
                                        "invalid_field": st.text(),
                                    }
                                )
                            ),
                        ),
                        "isError": st.one_of(
                            st.booleans(), st.just(None), st.integers(), st.text()
                        ),
                        "_meta": st.one_of(
                            st.fixed_dictionaries({"metadata": st.text()}),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_sampling_message() -> Dict[str, Any]:
        """Fuzz SamplingMessage with edge cases."""
        return st.fixed_dictionaries(
            {
                "role": st.one_of(
                    st.sampled_from(ROLES),
                    st.text(min_size=0, max_size=20),
                    st.just(""),
                    st.just("INVALID_ROLE"),
                    st.just("system"),
                    st.just("function"),
                    st.just("role-with-spaces"),
                    st.just("role-with-special-chars!@#"),
                    st.integers(),
                    st.floats(),
                    st.booleans(),
                    st.just(None),
                ),
                "content": st.one_of(
                    st.lists(
                        st.fixed_dictionaries(
                            {
                                "type": st.just("text"),
                                "text": st.text(
                                    min_size=0, max_size=10000
                                ),  # Very large prompts
                            }
                        )
                    ),
                    st.lists(
                        st.fixed_dictionaries(
                            {
                                "type": st.just("image"),
                                "data": st.text(
                                    min_size=0, max_size=100000
                                ),  # Large image data
                                "mimeType": st.text(min_size=0, max_size=100),
                            }
                        )
                    ),
                    st.lists(
                        st.fixed_dictionaries(
                            {
                                "type": st.text(min_size=0, max_size=20),
                                "invalid_content": st.text(),
                            }
                        )
                    ),
                ),
            }
        ).example()

    @staticmethod
    def fuzz_create_message_request() -> Dict[str, Any]:
        """Fuzz CreateMessageRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("sampling/createMessage"),
                "params": st.fixed_dictionaries(
                    {
                        "messages": st.lists(
                            st.fixed_dictionaries(
                                {
                                    "role": st.sampled_from(ROLES),
                                    "content": st.lists(
                                        st.fixed_dictionaries(
                                            {
                                                "type": st.just("text"),
                                                "text": st.text(
                                                    min_size=0, max_size=10000
                                                ),
                                            }
                                        )
                                    ),
                                }
                            ),
                            min_size=0,
                            max_size=100,  # Many messages
                        ),
                        "modelPreferences": st.one_of(
                            st.fixed_dictionaries(
                                {
                                    "hints": st.lists(
                                        st.fixed_dictionaries(
                                            {"name": st.text(min_size=0, max_size=100)}
                                        )
                                    ),
                                    "costPriority": st.floats(
                                        min_value=0.0, max_value=1.0
                                    ),
                                    "speedPriority": st.floats(
                                        min_value=0.0, max_value=1.0
                                    ),
                                    "intelligencePriority": st.floats(
                                        min_value=0.0, max_value=1.0
                                    ),
                                }
                            ),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        ),
                        "systemPrompt": st.one_of(
                            st.text(min_size=0, max_size=10000),
                            st.just(""),
                            st.just(None),
                        ),
                        "includeContext": st.one_of(
                            st.sampled_from(["none", "thisServer", "allServers"]),
                            st.text(min_size=0, max_size=20),
                            st.just(""),
                            st.just(None),
                        ),
                        "temperature": st.one_of(
                            st.floats(min_value=0.0, max_value=2.0),
                            st.floats(
                                min_value=-1.0, max_value=0.0
                            ),  # Invalid negative
                            st.floats(min_value=2.1, max_value=10.0),  # Invalid high
                            st.just(None),
                        ),
                        "maxTokens": st.one_of(
                            st.integers(min_value=1, max_value=10000),
                            st.integers(
                                min_value=-1000, max_value=0
                            ),  # Invalid negative
                            st.integers(
                                min_value=10001, max_value=100000
                            ),  # Very large
                            st.just(0),
                            st.just(None),
                        ),
                        "stopSequences": st.one_of(
                            st.lists(st.text(min_size=0, max_size=100)),
                            st.lists(
                                st.text(min_size=0, max_size=1000)
                            ),  # Very long sequences
                            st.just([]),
                            st.just(None),
                        ),
                        "metadata": st.one_of(
                            st.dictionaries(st.text(), st.text()),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_list_prompts_request() -> Dict[str, Any]:
        """Fuzz ListPromptsRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("prompts/list"),
                "params": st.fixed_dictionaries(
                    {
                        "cursor": st.one_of(
                            st.text(min_size=0, max_size=100),
                            st.just(""),
                            st.just(None),
                            st.text(min_size=0, max_size=10000),
                        ),
                        "_meta": st.one_of(
                            st.fixed_dictionaries(
                                {"progressToken": st.one_of(st.integers(), st.text())}
                            ),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_get_prompt_request() -> Dict[str, Any]:
        """Fuzz GetPromptRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("prompts/get"),
                "params": st.fixed_dictionaries(
                    {
                        "name": st.one_of(
                            st.text(min_size=1, max_size=100),
                            st.just(""),
                            st.just("invalid-prompt-name"),
                            st.just("prompt-with-spaces and special chars!@#"),
                            st.just("prompt-with-unicode-测试"),
                            st.text(min_size=0, max_size=1000),  # Very long names
                        ),
                        "arguments": st.one_of(
                            st.dictionaries(st.text(), st.text()),
                            st.fixed_dictionaries({}),
                            st.just(None),
                            st.dictionaries(
                                st.text(),
                                st.one_of(st.text(), st.integers(), st.booleans()),
                            ),
                        ),
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_list_roots_request() -> Dict[str, Any]:
        """Fuzz ListRootsRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("roots/list"),
                "params": st.fixed_dictionaries(
                    {
                        "_meta": st.one_of(
                            st.fixed_dictionaries(
                                {"progressToken": st.one_of(st.integers(), st.text())}
                            ),
                            st.fixed_dictionaries({}),
                            st.just(None),
                        )
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_subscribe_request() -> Dict[str, Any]:
        """Fuzz SubscribeRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("resources/subscribe"),
                "params": st.fixed_dictionaries(
                    {
                        "uri": st.one_of(
                            st.just("file:///path/to/resource"),
                            st.just("http://example.com/resource"),
                            st.just("https://example.com/resource"),
                            st.just("invalid://uri"),
                            st.just(""),
                            st.just("not-a-uri"),
                            st.just("file:///path/with/spaces and special chars!@#"),
                            st.just("file:///path/with/unicode/测试"),
                            st.just("file:///path/with/very/long/path/" + "a" * 1000),
                            st.just("file:///path/with/../relative/path"),
                            st.just("file:///path/with/../../../../../etc/passwd"),
                        )
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_unsubscribe_request() -> Dict[str, Any]:
        """Fuzz UnsubscribeRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("resources/unsubscribe"),
                "params": st.fixed_dictionaries(
                    {
                        "uri": st.one_of(
                            st.just("file:///path/to/resource"),
                            st.just("http://example.com/resource"),
                            st.just("https://example.com/resource"),
                            st.just("invalid://uri"),
                            st.just(""),
                            st.just("not-a-uri"),
                            st.just("file:///path/with/spaces and special chars!@#"),
                            st.just("file:///path/with/unicode/测试"),
                            st.just("file:///path/with/very/long/path/" + "a" * 1000),
                            st.just("file:///path/with/../relative/path"),
                            st.just("file:///path/with/../../../../../etc/passwd"),
                        )
                    }
                ),
            }
        ).example()

    @staticmethod
    def fuzz_complete_request() -> Dict[str, Any]:
        """Fuzz CompleteRequest with edge cases."""
        return st.fixed_dictionaries(
            {
                "jsonrpc": st.just(JSONRPC_VERSION),
                "id": st.one_of(st.integers(), st.text()),
                "method": st.just("completion/complete"),
                "params": st.fixed_dictionaries(
                    {
                        "ref": st.one_of(
                            st.fixed_dictionaries(
                                {
                                    "type": st.just("ref/resource"),
                                    "uri": st.text(min_size=0, max_size=1000),
                                }
                            ),
                            st.fixed_dictionaries(
                                {
                                    "type": st.just("ref/prompt"),
                                    "name": st.text(min_size=0, max_size=100),
                                }
                            ),
                            st.fixed_dictionaries(
                                {
                                    "type": st.text(min_size=0, max_size=20),
                                    "invalid_field": st.text(),
                                }
                            ),
                        ),
                        "argument": st.fixed_dictionaries(
                            {
                                "name": st.one_of(
                                    st.text(min_size=1, max_size=50),
                                    st.just(""),
                                    st.text(min_size=0, max_size=1000),
                                ),
                                "value": st.one_of(
                                    st.text(min_size=0, max_size=1000),
                                    st.just(""),
                                    st.text(
                                        min_size=0, max_size=10000
                                    ),  # Very long values
                                ),
                            }
                        ),
                    }
                ),
            }
        ).example()

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
