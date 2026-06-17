"""Coverage tests for stateful protocol fuzzing paths."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.client.protocol_client import ProtocolClient
from mcp_fuzzer.exceptions import ServerCrashError

pytestmark = [pytest.mark.unit, pytest.mark.client]


@pytest.fixture
def client():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": {"ok": True}})
    transport.send_notification = AsyncMock(return_value=None)
    return ProtocolClient(transport=transport, safety_system=None)


@pytest.mark.asyncio
async def test_fuzz_stateful_sequences_zero_runs(client):
    assert await client.fuzz_stateful_sequences(runs=0) == []


@pytest.mark.asyncio
async def test_build_stateful_sequence_uses_observed_entities(client, monkeypatch):
    client._observed_resources.add("file:///x")
    client._observed_prompts.add("prompt-x")
    client._observed_tools["tool-x"] = {
        "name": "tool-x",
        "inputSchema": {"type": "object", "required": [], "properties": {}},
        "execution": {"taskSupport": "optional"},
    }
    client._observed_tasks["task-x"] = {"taskId": "task-x", "status": "running"}

    async def fake_pick(protocol_type, phase):
        return {"jsonrpc": "2.0", "method": protocol_type, "params": {}}

    monkeypatch.setattr(client, "_pick_learned_request", fake_pick)

    sequence = await client._build_stateful_sequence("realistic")
    protocol_types = [step[0] for step in sequence]

    assert "ReadResourceRequest" in protocol_types
    assert "GetPromptRequest" in protocol_types
    assert "CallToolRequest" in protocol_types
    assert "ListTasksRequest" in protocol_types
    assert "GetTaskRequest" in protocol_types


@pytest.mark.asyncio
async def test_pick_learned_request_prefers_success_pool(client, monkeypatch):
    client._successful_requests["PingRequest"] = [
        {"jsonrpc": "2.0", "method": "ping", "params": {"x": 1}}
    ]
    monkeypatch.setattr(
        "mcp_fuzzer.client.protocol_client.mutate_seed_payload",
        lambda base, stack=1: {"params": {"x": 2}},
    )

    picked = await client._pick_learned_request("PingRequest", "realistic")
    assert picked["jsonrpc"] == "2.0"
    assert picked["method"] == "ping"


@pytest.mark.asyncio
async def test_pick_learned_request_falls_back_on_mutator_error(client):
    client.protocol_mutator.mutate = AsyncMock(side_effect=RuntimeError("boom"))
    picked = await client._pick_learned_request("PingRequest", "realistic")
    assert picked["method"] == "unknown"


@pytest.mark.asyncio
async def test_execute_protocol_fuzz_records_jsonrpc_error(
    client, monkeypatch
):
    client._send_protocol_request = AsyncMock(
        return_value={"error": {"code": -32600, "message": "bad"}}
    )
    monkeypatch.setattr(
        client.protocol_mutator,
        "record_feedback",
        lambda *args, **kwargs: None,
    )

    result = await client._execute_protocol_fuzz(
        "PingRequest",
        {"jsonrpc": "2.0", "method": "ping", "params": {}},
        "ping-1",
    )

    assert result["server_rejected_input"] is True
    assert result["success"] is True


@pytest.mark.asyncio
async def test_execute_protocol_fuzz_records_server_crash(client, monkeypatch):
    crash = ServerCrashError("died", context={"exit_code": 1})
    client._send_protocol_request = AsyncMock(side_effect=crash)
    monkeypatch.setattr(
        client.protocol_mutator,
        "record_feedback",
        lambda *args, **kwargs: None,
    )

    result = await client._execute_protocol_fuzz(
        "PingRequest",
        {"jsonrpc": "2.0", "method": "ping", "params": {}},
        "ping-crash",
    )

    assert result["outcome"] == "crashed"
    assert result["crash"]["exit_code"] == 1
