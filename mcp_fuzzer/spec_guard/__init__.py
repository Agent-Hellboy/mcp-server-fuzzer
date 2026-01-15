"""Spec guard helpers for MCP Fuzzer."""

from .helpers import SpecCheck
from .spec_checks import (
    check_tool_result_content,
    check_tool_schema_fields,
    check_logging_notification,
    check_resources_list,
    check_resources_read,
    check_resource_templates_list,
    check_prompts_list,
    check_prompts_get,
    check_sse_event_text,
)
from .runner import run_spec_suite
from .schema_validator import validate_definition
from .mappings import (
    METHOD_CHECK_MAP,
    PROTOCOL_TYPE_TO_METHOD,
    get_spec_checks_for_method,
    get_spec_checks_for_protocol_type,
)

__all__ = [
    "SpecCheck",
    "check_tool_result_content",
    "check_tool_schema_fields",
    "check_logging_notification",
    "check_resources_list",
    "check_resources_read",
    "check_resource_templates_list",
    "check_prompts_list",
    "check_prompts_get",
    "check_sse_event_text",
    "run_spec_suite",
    "validate_definition",
    "METHOD_CHECK_MAP",
    "PROTOCOL_TYPE_TO_METHOD",
    "get_spec_checks_for_method",
    "get_spec_checks_for_protocol_type",
]
