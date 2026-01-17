#!/usr/bin/env python3
"""Tests for MCP spec guard check helpers."""

from __future__ import annotations

from mcp_fuzzer.spec_guard import spec_checks


def test_check_tool_schema_fields_reports_errors():
    checks = spec_checks.check_tool_schema_fields(
        {
            "inputSchema": {
                "$schema": 123,
                "$defs": "not-dict",
                "additionalProperties": [],
            }
        }
    )
    ids = {check["id"] for check in checks}
    assert "tool-schema-$schema" in ids
    assert "tool-schema-$defs" in ids
    assert "tool-schema-additional-properties" in ids


def test_check_tool_result_content_flags_multiple_issues():
    checks = spec_checks.check_tool_result_content(
        {
            "content": [
                "not-an-object",
                {"foo": "bar"},
                {"type": "text", "text": ""},
                {"type": "resource", "resource": {"uri": "u"}},
            ],
            "isError": True,
        }
    )
    ids = [check["id"] for check in checks]
    assert "tools-content-item" in ids
    assert "tools-content-type" in ids
    assert "tools-content-text" in ids
    assert "tools-content-resource-mime" in ids or "tools-content-resource-body" in ids
    assert "tools-error-text" in ids


def test_check_resources_list_handles_missing_fields():
    checks = spec_checks.check_resources_list(
        {"resources": ["bad", {"name": "ok"}, {"uri": "uri"}]}
    )
    ids = {check["id"] for check in checks}
    assert "resources-list-item" in ids
    assert "resources-list-name" in ids
    assert "resources-list-uri" in ids


def test_check_resources_read_requires_content_and_body():
    checks = spec_checks.check_resources_read({"contents": [{"uri": "u", "text": ""}]})
    ids = {check["id"] for check in checks}
    assert "resources-read-body" in ids

    empty_checks = spec_checks.check_resources_read({})
    assert empty_checks and empty_checks[0]["id"] == "resources-read-missing"


def test_check_prompts_get_reports_missing_fields():
    checks = spec_checks.check_prompts_get({"messages": [{"role": "", "content": ""}]})
    ids = {check["id"] for check in checks}
    assert "prompts-get-role" in ids
    assert "prompts-get-content" in ids

    assert (
        spec_checks.check_prompts_get({"messages": []})[0]["id"] == "prompts-get-empty"
    )


def test_check_sse_event_text_warns_on_invalid_fields():
    checks = spec_checks.check_sse_event_text("retry: abc\nid:\n")
    ids = {check["id"] for check in checks}
    assert "sse-retry-nonint" in ids
    assert "sse-id-empty" in ids
    assert "sse-no-data" in ids


def test_check_tool_schema_fields_allows_valid_schema_entries():
    checks = spec_checks.check_tool_schema_fields(
        {
            "inputSchema": {
                "$schema": "https://example.com/schema",
                "$defs": {"inner": {"type": "object"}},
                "additionalProperties": False,
            }
        }
    )
    assert checks == []


def test_check_tool_result_content_detects_invalid_content_container():
    checks = spec_checks.check_tool_result_content({"content": "not-list"})
    assert any(check["id"] == "tools-content-array" for check in checks)


def test_check_tool_result_content_fails_when_empty_and_error():
    checks = spec_checks.check_tool_result_content({"content": [], "isError": True})
    ids = {check["id"] for check in checks}
    assert "tools-content-empty" in ids
    assert "tools-error-text" in ids


def test_check_tool_result_content_warns_unknown_content_type():
    checks = spec_checks.check_tool_result_content(
        {"content": [{"type": "alien", "data": "hi"}]}
    )
    assert any(check["id"] == "tools-content-unknown-type" for check in checks)


def test_check_logging_notification_reports_invalid_params():
    checks = spec_checks.check_logging_notification(
        {"params": {"level": 1, "logger": ["array"]}}
    )
    assert any(check["id"] == "logging-level-type" for check in checks)
    assert any(check["id"] == "logging-data-missing" for check in checks)
    assert any(check["id"] == "logging-logger-type" for check in checks)


def test_check_logging_notification_accepts_valid_data():
    checks = spec_checks.check_logging_notification(
        {"params": {"level": "info", "data": "ok"}}
    )
    assert checks == []


def test_check_resources_list_catches_missing_and_bad_types():
    missing = spec_checks.check_resources_list({})
    assert missing and missing[0]["id"] == "resources-list-missing"

    wrong_type = spec_checks.check_resources_list({"resources": "not-list"})
    assert wrong_type and wrong_type[0]["id"] == "resources-list-type"


def test_check_resources_read_validates_content_items():
    item_checks = spec_checks.check_resources_read({"contents": ["string"]})
    assert any(check["id"] == "resources-read-item" for check in item_checks)

    empty_checks = spec_checks.check_resources_read({"contents": []})
    assert any(check["id"] == "resources-read-empty" for check in empty_checks)


def test_check_resource_templates_list_flag_missing_uri_template():
    checks = spec_checks.check_resource_templates_list(
        {"resourceTemplates": [{"name": "template"}]}
    )
    assert any(check["id"] == "resources-templates-uri" for check in checks)


def test_check_prompts_list_flags_missing_fields():
    checks = spec_checks.check_prompts_list(
        {
            "prompts": [
                "not-dict",
                {"name": ""},
            ]
        }
    )
    ids = {check["id"] for check in checks}
    assert "prompts-list-item" in ids
    assert "prompts-list-name" in ids

    wrong_type = spec_checks.check_prompts_list({"prompts": "not-list"})
    assert wrong_type and wrong_type[0]["id"] == "prompts-list-type"


def test_check_prompts_get_reports_missing_or_bad_messages():
    missing = spec_checks.check_prompts_get({})
    assert missing and missing[0]["id"] == "prompts-get-missing"

    wrong_type = spec_checks.check_prompts_get({"messages": "bad"})
    assert wrong_type and wrong_type[0]["id"] == "prompts-get-type"


def test_check_sse_event_text_no_warnings_when_data_present():
    checks = spec_checks.check_sse_event_text("data: ok\nretry: 200\nid: evt1\n")
    assert checks == []
