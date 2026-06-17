"""Coverage tests for protocol listing discovery and follow-up fuzzing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.client.protocol_client import ProtocolClient

pytestmark = [pytest.mark.unit, pytest.mark.client]


@pytest.fixture
def client():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": {}})
    return ProtocolClient(transport=transport, safety_system=None)


def test_extract_list_items_and_payloads(client):
    assert client._extract_list_items({"tools": [{"name": "a"}]}, "tools") == [
        {"name": "a"}
    ]
    assert client._extract_list_items(
        {"result": {"prompts": [{"name": "p"}]}}, "prompts"
    ) == [{"name": "p"}]
    assert client._extract_list_items("bad", "tools") == []

    payloads = client._extract_payload_dicts(
        {"result": {"taskId": "t1", "status": "x"}}
    )
    assert len(payloads) == 2


def test_remember_and_choose_observed_entities(client):
    client._remember_tool("bad")
    client._remember_tool({"name": ""})
    client._remember_tool(
        {
            "name": "direct",
            "inputSchema": {"type": "object", "required": [], "properties": {}},
        }
    )
    client._remember_tool(
        {
            "name": "tasky",
            "inputSchema": {"type": "object", "required": [], "properties": {}},
            "execution": {"taskSupport": "required"},
        }
    )
    client._remember_task({"taskId": "task-1", "status": "running"})

    assert client._choose_observed_tool(allow_task_required=False)["name"] == "direct"
    assert client._choose_observed_tool(require_task_support=True)["name"] == "tasky"
    assert client._choose_observed_task()["taskId"] == "task-1"


def test_record_successful_request_tracks_entities(client):
    client._max_successful_requests = 2
    response = {
        "resources": [{"uri": "file:///a"}],
        "prompts": [{"name": "prompt-a"}],
        "tools": [
            {
                "name": "tool-a",
                "inputSchema": {"type": "object", "required": [], "properties": {}},
            }
        ],
        "tasks": [{"taskId": "task-2", "status": "completed"}],
        "task": {"taskId": "task-3", "status": "working"},
    }
    client._record_successful_request(
        "ListToolsRequest",
        {"method": "tools/list"},
        response,
    )

    assert "file:///a" in client._observed_resources
    assert "prompt-a" in client._observed_prompts
    assert "tool-a" in client._observed_tools
    assert "task-2" in client._observed_tasks
    assert "task-3" in client._observed_tasks
    assert len(client._successful_requests["ListToolsRequest"]) == 1

    client._record_successful_request("ListToolsRequest", {"method": "x"}, response)
    client._record_successful_request("ListToolsRequest", {"method": "y"}, response)
    assert len(client._successful_requests["ListToolsRequest"]) == 2


@pytest.mark.asyncio
async def test_fetch_listed_items_handles_transport_error(client):
    client.transport.send_request = AsyncMock(side_effect=RuntimeError("down"))
    items = await client._fetch_listed_tools()
    assert items == []


@pytest.mark.asyncio
async def test_fuzz_listed_resources(client):
    client.transport.send_request = AsyncMock(
        return_value={"resources": [{"uri": "file:///r"}]}
    )
    client._execute_protocol_fuzz = AsyncMock(return_value={"success": True})

    resource_results = await client._fuzz_listed_resources()
    assert len(resource_results) == 1


@pytest.mark.asyncio
async def test_fuzz_listed_prompts(client):
    client.transport.send_request = AsyncMock(
        return_value={"prompts": [{"name": "p1"}]}
    )
    client._execute_protocol_fuzz = AsyncMock(return_value={"success": True})

    prompt_results = await client._fuzz_listed_prompts()
    assert len(prompt_results) == 1


@pytest.mark.asyncio
async def test_fuzz_listed_tools_with_task_support(client):
    client.transport.send_request = AsyncMock(
        return_value={
            "tools": [
                {
                    "name": "sync",
                    "inputSchema": {"type": "object", "required": [], "properties": {}},
                    "execution": {"taskSupport": "optional"},
                }
            ]
        }
    )
    client._execute_protocol_fuzz = AsyncMock(return_value={"success": True})

    results = await client._fuzz_listed_tools()
    assert len(results) == 2
    labels = [call.args[2] for call in client._execute_protocol_fuzz.await_args_list]
    assert "tool:sync" in labels
    assert "tool-task:sync" in labels


@pytest.mark.asyncio
async def test_fuzz_observed_tasks_filters_by_protocol_type(client):
    client._observed_tasks["task-9"] = {"taskId": "task-9", "status": "running"}
    client._execute_protocol_fuzz = AsyncMock(return_value={"success": True})

    results = await client._fuzz_observed_tasks(protocol_type="GetTaskRequest")
    assert len(results) == 1
    assert client._execute_protocol_fuzz.await_args.args[0] == "GetTaskRequest"
