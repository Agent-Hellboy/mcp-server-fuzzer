#!/usr/bin/env python3
"""
Unit tests for spec_guard.runner.
"""

from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.spec_guard import runner


def test_parse_prompt_args_invalid_json():
    with pytest.raises(ValueError, match="spec_prompt_args is not valid JSON"):
        runner._parse_prompt_args("{bad")


def test_parse_prompt_args_non_object():
    with pytest.raises(ValueError, match="spec_prompt_args must be a JSON object"):
        runner._parse_prompt_args("[1, 2]")


@pytest.mark.asyncio
async def test_run_spec_suite_initialize_failure():
    transport = MagicMock()

    async def _send_request(method, params=None):
        raise RuntimeError("boom")

    async def _send_notification(method, params=None):
        return None

    transport.send_request = _send_request
    transport.send_notification = _send_notification

    checks = await runner.run_spec_suite(transport)

    assert checks
    assert checks[0]["status"] == "FAIL"


@pytest.mark.asyncio
async def test_run_spec_suite_full_paths(monkeypatch):
    calls = []

    async def _send_request(method, params=None):
        calls.append(method)
        if method == "initialize":
            return {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {},
                    "completions": {},
                }
            }
        if method == "tools/list":
            return {"tools": [{"name": "alpha", "inputSchema": {"required": []}}]}
        return {}

    async def _send_notification(method, params=None):
        calls.append(method)
        return None

    transport = type("T", (), {})()
    transport.send_request = _send_request
    transport.send_notification = _send_notification

    monkeypatch.setattr(runner, "validate_definition", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_tool_schema_fields", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_resources_list", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_resources_read", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        runner,
        "check_resource_templates_list",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(runner, "check_prompts_list", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_prompts_get", lambda *args, **kwargs: [])

    checks = await runner.run_spec_suite(
        transport,
        resource_uri="resource://x",
        prompt_name="p",
        prompt_args='{"q":"x"}',
    )

    assert checks == []
    assert "initialize" in calls
    assert "tools/list" in calls
    assert "tools/call" in calls
    assert "resources/list" in calls
    assert "resources/templates/list" in calls
    assert "resources/read" in calls
    assert "prompts/list" in calls
    assert "prompts/get" in calls
    assert "completion/complete" in calls
