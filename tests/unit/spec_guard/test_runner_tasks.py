"""Coverage tests for task-related spec_guard runner paths."""

from __future__ import annotations

import pytest

from mcp_fuzzer.spec_guard import runner

pytestmark = [pytest.mark.unit]


@pytest.mark.asyncio
async def test_run_spec_suite_tasks_capability_paths(monkeypatch):
    calls: list[str] = []

    async def _send_request(method, params=None):
        calls.append(method)
        if method == "initialize":
            return {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tools": {"listChanged": True},
                    "tasks": {"list": {}, "cancel": {}},
                },
            }
        if method == "tools/list":
            return {
                "tools": [
                    {
                        "name": "task-tool",
                        "inputSchema": {
                            "type": "object",
                            "required": [],
                            "properties": {},
                        },
                        "execution": {"taskSupport": "optional"},
                    }
                ]
            }
        if method == "tools/call":
            return {"task": {"taskId": "task-from-call", "status": "working"}}
        if method == "tasks/list":
            return {"tasks": [{"taskId": "task-from-list", "status": "working"}]}
        return {"taskId": params.get("taskId") if isinstance(params, dict) else None}

    async def _send_notification(method, params=None):
        calls.append(method)
        return None

    transport = type("T", (), {})()
    transport.send_request = _send_request
    transport.send_notification = _send_notification

    monkeypatch.setattr(runner, "validate_definition", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_tool_schema_fields", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_task_result", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_tasks_list", lambda *args, **kwargs: [])
    monkeypatch.setattr(runner, "check_task_payload_result", lambda *args, **kwargs: [])

    checks = await runner.run_spec_suite(transport)

    assert checks == []
    assert "tools/call" in calls
    assert "tasks/list" in calls
    assert "tasks/get" in calls
    assert "tasks/result" in calls
    assert "tasks/cancel" in calls
