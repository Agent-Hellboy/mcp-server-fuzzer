#!/usr/bin/env python3
"""Tests for spec guard runner behavior."""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_fuzzer.spec_guard import runner

pytestmark = [pytest.mark.unit]


class FakeTransport:
    """Minimal async transport stub for spec guard tests."""

    def __init__(self, responses: dict[str, Any]):
        self.responses = responses
        self.requests: list[tuple[str, Any]] = []
        self.notifications: list[str] = []

    async def send_request(self, method: str, params: Any | None = None) -> Any:
        self.requests.append((method, params))
        response = self.responses.get(method)
        if isinstance(response, Exception):
            raise response
        return response

    async def send_notification(self, method: str) -> None:
        self.notifications.append(method)


def test_parse_prompt_args_none():
    assert runner._parse_prompt_args(None) is None


def test_parse_prompt_args_invalid_json():
    with pytest.raises(ValueError, match="spec_prompt_args is not valid JSON"):
        runner._parse_prompt_args("{not-json}")


def test_parse_prompt_args_non_object():
    with pytest.raises(ValueError, match="spec_prompt_args must be a JSON object"):
        runner._parse_prompt_args(json.dumps(["not", "object"]))


def test_parse_prompt_args_valid_object():
    assert runner._parse_prompt_args(json.dumps({"a": 1})) == {"a": 1}


@pytest.mark.asyncio
async def test_run_spec_suite_initialize_failure(monkeypatch):
    transport = FakeTransport({"initialize": RuntimeError("boom")})
    checks = await runner.run_spec_suite(transport)

    assert checks
    assert checks[0]["id"] == "initialize"
    assert checks[0]["status"] == "FAIL"


@pytest.mark.asyncio
async def test_run_spec_suite_tools_warns_when_no_callable_tool(monkeypatch):
    monkeypatch.setattr(runner, "validate_definition", lambda *_: [])
    monkeypatch.setattr(runner, "check_tool_schema_fields", lambda *_: [])

    transport = FakeTransport(
        {
            "initialize": {"capabilities": {"tools": {}}},
            "ping": {},
            "tools/list": {
                "tools": [
                    {
                        "name": "t1",
                        "inputSchema": {"required": ["x"]},
                    }
                ]
            },
        }
    )

    checks = await runner.run_spec_suite(transport)

    assert any(
        check["id"] == "tools-call" and check["status"] == "WARN" for check in checks
    )


@pytest.mark.asyncio
async def test_run_spec_suite_prompts_and_completion(monkeypatch):
    monkeypatch.setattr(runner, "validate_definition", lambda *_: [])
    monkeypatch.setattr(runner, "check_prompts_list", lambda *_: [])
    monkeypatch.setattr(runner, "check_prompts_get", lambda *_: [])

    transport = FakeTransport(
        {
            "initialize": {"capabilities": {"prompts": {}, "completions": {}}},
            "ping": {},
            "prompts/list": {"prompts": []},
            "prompts/get": {"messages": []},
            "completion/complete": {"completion": {"type": "text", "value": "ok"}},
        }
    )

    checks = await runner.run_spec_suite(
        transport,
        prompt_name="demo",
        prompt_args="{}",
    )

    methods = [method for method, _params in transport.requests]
    assert "prompts/get" in methods
    assert "completion/complete" in methods
    assert checks is not None
