from __future__ import annotations

import json
import pytest

from mcp_fuzzer.spec_guard import runner


class DummyTransport:
    def __init__(self, responses: dict[str, object]):
        self.responses = responses
        self.notifications: list[str] = []

    async def send_request(self, method: str, params: object | None = None) -> object:
        if method not in self.responses:
            raise AssertionError(f"Unexpected request: {method}")
        response = self.responses[method]
        if isinstance(response, Exception):
            raise response
        return response

    async def send_notification(
        self, method: str, params: object | None = None
    ) -> None:
        if method not in self.responses:
            raise AssertionError(f"Unexpected notification: {method}")
        response = self.responses[method]
        if isinstance(response, Exception):
            raise response
        self.notifications.append(method)


def test_parse_prompt_args_success_and_errors():
    assert runner._parse_prompt_args('{"foo": 1}') == {"foo": 1}
    with pytest.raises(ValueError):
        runner._parse_prompt_args("not json")
    with pytest.raises(ValueError):
        runner._parse_prompt_args("[]")
    assert runner._parse_prompt_args(None) is None


@pytest.mark.asyncio
async def test_run_spec_suite_success_flow(monkeypatch):
    events: list[str] = []

    def fake_validate_definition(name: str, result: object, **_: object) -> list[str]:
        events.append(f"validate:{name}")
        return [name]

    def fake_check_tools_list(tool: object) -> list[str]:
        events.append("check_tool_schema_fields")
        return ["tool-checked"]

    def fake_check_resources_list(result: object) -> list[str]:
        events.append("resources_list")
        return ["resources"]

    def fake_check_resource_templates_list(result: object) -> list[str]:
        events.append("resources_templates")
        return ["templates"]

    def fake_check_resources_read(result: object) -> list[str]:
        events.append("resources_read")
        return ["read"]

    def fake_check_prompts_list(result: object) -> list[str]:
        events.append("prompts_list")
        return ["prompts"]

    def fake_check_prompts_get(result: object) -> list[str]:
        events.append("prompts_get")
        return ["prompt"]

    monkeypatch.setattr(runner, "validate_definition", fake_validate_definition)
    monkeypatch.setattr(runner, "check_tool_schema_fields", fake_check_tools_list)
    monkeypatch.setattr(runner, "check_resources_list", fake_check_resources_list)
    monkeypatch.setattr(
        runner, "check_resource_templates_list", fake_check_resource_templates_list
    )
    monkeypatch.setattr(runner, "check_resources_read", fake_check_resources_read)
    monkeypatch.setattr(runner, "check_prompts_list", fake_check_prompts_list)
    monkeypatch.setattr(runner, "check_prompts_get", fake_check_prompts_get)

    responses = {
        "initialize": {
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": True,
                "resources": True,
                "prompts": True,
                "completions": True,
            },
        },
        "ping": {},
        "notifications/initialized": None,
        "tools/list": {"tools": [{"name": "alpha", "inputSchema": {"required": []}}]},
        "tools/call": {"result": "ok"},
        "resources/list": {"resources": []},
        "resources/templates/list": {"templates": []},
        "resources/read": {"uri": "foo"},
        "prompts/list": {"prompts": []},
        "prompts/get": {"prompt": "x"},
        "completion/complete": {"completion": "done"},
    }
    transport = DummyTransport(responses)

    checks = await runner.run_spec_suite(
        transport,
        resource_uri="foo",
        prompt_name="prompt-name",
        prompt_args=json.dumps({"foo": "bar"}),
    )

    assert any(entry.startswith("validate:") for entry in events)
    assert "InitializeResult" in checks
    assert transport.notifications == ["notifications/initialized"]


@pytest.mark.asyncio
async def test_run_spec_suite_handles_tool_list_failure(monkeypatch):
    failure: list[str] = []

    def fake_fail(scope: str, message: str, spec: object) -> dict[str, object]:
        failure.append(scope)
        return {"scope": scope, "message": message}

    monkeypatch.setattr(runner, "validate_definition", lambda name, result, **_: [])
    monkeypatch.setattr(runner, "check_tool_schema_fields", lambda tool: [])
    monkeypatch.setattr(runner, "_fail", fake_fail)

    responses = {
        "initialize": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": True},
        },
        "ping": {},
        "notifications/initialized": None,
        "tools/list": RuntimeError("boom"),
    }
    transport = DummyTransport(responses)
    checks = await runner.run_spec_suite(transport)
    assert any(
        isinstance(entry, dict) and entry.get("scope") == "tools-list"
        for entry in checks
    )


@pytest.mark.asyncio
async def test_run_spec_suite_fails_without_protocol_version():
    responses = {
        "initialize": {"capabilities": {"tools": True}},
        "ping": {},
        "notifications/initialized": None,
    }
    transport = DummyTransport(responses)

    checks = await runner.run_spec_suite(transport)

    assert any(
        isinstance(entry, dict) and entry.get("id") == "protocol-version"
        for entry in checks
    )


@pytest.mark.asyncio
async def test_run_spec_suite_rejects_invalid_protocol_version():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "bad-version",
                "capabilities": {},
            },
            "notifications/initialized": None,
            "ping": {},
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(check.get("id") == "protocol-version" for check in checks)


@pytest.mark.asyncio
async def test_run_spec_suite_initialize_result_non_dict():
    transport = DummyTransport(
        {
            "initialize": ["not-a-dict"],
            "notifications/initialized": None,
            "ping": {},
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(check.get("id") == "protocol-version" for check in checks)


@pytest.mark.asyncio
async def test_run_spec_suite_ping_failure():
    transport = DummyTransport(
        {
            "initialize": {"protocolVersion": "2025-11-25", "capabilities": {}},
            "notifications/initialized": None,
            "ping": RuntimeError("boom"),
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(check.get("id") == "ping" for check in checks)


@pytest.mark.asyncio
async def test_run_spec_suite_tools_call_failure():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": True},
            },
            "notifications/initialized": None,
            "ping": {},
            "tools/list": {"tools": [{"name": "t", "inputSchema": {"required": []}}]},
            "tools/call": RuntimeError("boom"),
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(check.get("id") == "tools-call" for check in checks)


@pytest.mark.asyncio
async def test_run_spec_suite_warns_when_no_callable_tool():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": True},
            },
            "notifications/initialized": None,
            "ping": {},
            "tools/list": {
                "tools": [{"name": "t", "inputSchema": {"required": ["x"]}}]
            },
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(
        check.get("id") == "tools-call" and check.get("status") == "WARN"
        for check in checks
    )


@pytest.mark.asyncio
async def test_run_spec_suite_resource_failures():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"resources": True},
            },
            "notifications/initialized": None,
            "ping": {},
            "resources/list": RuntimeError("boom"),
            "resources/templates/list": RuntimeError("boom"),
            "resources/read": RuntimeError("boom"),
        }
    )
    checks = await runner.run_spec_suite(transport, resource_uri="resource://x")
    ids = {check.get("id") for check in checks if isinstance(check, dict)}
    assert "resources-list" in ids
    assert "resources-templates-list" in ids
    assert "resources-read" in ids


@pytest.mark.asyncio
async def test_run_spec_suite_prompt_failures_and_completion_warning():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"prompts": True, "completions": True},
            },
            "notifications/initialized": None,
            "ping": {},
            "prompts/list": RuntimeError("boom"),
            "prompts/get": RuntimeError("boom"),
        }
    )
    checks = await runner.run_spec_suite(transport, prompt_name="p")
    ids = {check.get("id") for check in checks if isinstance(check, dict)}
    assert "prompts-list" in ids
    assert "prompts-get" in ids


@pytest.mark.asyncio
async def test_run_spec_suite_completion_warns_without_prompt():
    transport = DummyTransport(
        {
            "initialize": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"completions": True},
            },
            "notifications/initialized": None,
            "ping": {},
        }
    )
    checks = await runner.run_spec_suite(transport)
    assert any(check.get("id") == "completion-complete" for check in checks)
