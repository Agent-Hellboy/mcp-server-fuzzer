"""
Aggressive Strategy Module

This module contains strategies for generating malicious, malformed, and edge-case
data for fuzzing. The aggressive phase tests server security and robustness with
attack vectors and invalid inputs.
"""

from .tool_strategy import (
    generate_aggressive_text,
    fuzz_tool_arguments_aggressive,
)

from .protocol_type_strategy import (
    fuzz_initialize_request_aggressive,
    fuzz_progress_notification,
    fuzz_cancel_notification,
    fuzz_list_resources_request,
    fuzz_read_resource_request,
    fuzz_set_level_request,
    fuzz_generic_jsonrpc_request,
    fuzz_call_tool_result,
    fuzz_sampling_message,
    fuzz_create_message_request,
    fuzz_list_prompts_request,
    fuzz_get_prompt_request,
    fuzz_list_roots_request,
    fuzz_subscribe_request,
    fuzz_unsubscribe_request,
    fuzz_complete_request,
    get_protocol_fuzzer_method,
)

__all__ = [
    # Tool strategies
    "generate_aggressive_text",
    "fuzz_tool_arguments_aggressive",
    # Protocol strategies
    "fuzz_initialize_request_aggressive",
    "fuzz_progress_notification",
    "fuzz_cancel_notification",
    "fuzz_list_resources_request",
    "fuzz_read_resource_request",
    "fuzz_set_level_request",
    "fuzz_generic_jsonrpc_request",
    "fuzz_call_tool_result",
    "fuzz_sampling_message",
    "fuzz_create_message_request",
    "fuzz_list_prompts_request",
    "fuzz_get_prompt_request",
    "fuzz_list_roots_request",
    "fuzz_subscribe_request",
    "fuzz_unsubscribe_request",
    "fuzz_complete_request",
    "get_protocol_fuzzer_method",
]
