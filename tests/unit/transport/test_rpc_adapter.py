#!/usr/bin/env python3
"""
Unit tests for JsonRpcAdapter.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.transport.interfaces.rpc_adapter import JsonRpcAdapter


def test_require_transport_raises():
    adapter = JsonRpcAdapter()

    with pytest.raises(RuntimeError):
        adapter._require_transport()


@pytest.mark.asyncio
async def test_get_tools_from_top_level():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"tools": [{"name": "t"}]})
    adapter = JsonRpcAdapter(transport)

    tools = await adapter.get_tools()

    assert tools == [{"name": "t"}]


@pytest.mark.asyncio
async def test_get_tools_from_result():
    transport = MagicMock()
    transport.send_request = AsyncMock(
        return_value={"result": {"tools": [{"name": "t"}]}}
    )
    adapter = JsonRpcAdapter(transport)

    tools = await adapter.get_tools()

    assert tools == [{"name": "t"}]


@pytest.mark.asyncio
async def test_get_tools_error_returns_empty():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"error": "boom"})
    adapter = JsonRpcAdapter(transport)

    tools = await adapter.get_tools()

    assert tools == []


@pytest.mark.asyncio
async def test_get_tools_missing_key_returns_empty():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": {"nope": []}})
    adapter = JsonRpcAdapter(transport)

    tools = await adapter.get_tools()

    assert tools == []


@pytest.mark.asyncio
async def test_call_tool_sends_request():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    adapter = JsonRpcAdapter(transport)

    result = await adapter.call_tool("alpha", {"x": 1})

    assert result == {"ok": True}
    transport.send_request.assert_called_once_with(
        "tools/call", {"name": "alpha", "arguments": {"x": 1}}
    )


@pytest.mark.asyncio
async def test_complete_argument_shapes():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    adapter = JsonRpcAdapter(transport)

    await adapter.complete("prompt", {})
    transport.send_request.assert_called_with(
        "completion/complete",
        {
            "ref": {"type": "ref/prompt", "name": "prompt"},
            "argument": {"name": "query", "value": ""},
        },
    )

    await adapter.complete("prompt", {"x": "y"})
    transport.send_request.assert_called_with(
        "completion/complete",
        {
            "ref": {"type": "ref/prompt", "name": "prompt"},
            "argument": {"name": "x", "value": "y"},
        },
    )

    await adapter.complete("prompt", {"x": "y", "z": "w"})
    transport.send_request.assert_called_with(
        "completion/complete",
        {
            "ref": {"type": "ref/prompt", "name": "prompt"},
            "argument": [{"name": "x", "value": "y"}, {"name": "z", "value": "w"}],
        },
    )


@pytest.mark.asyncio
async def test_send_batch_request_mixed():
    transport = MagicMock()
    transport.send_raw = AsyncMock(side_effect=[None, {"result": {"ok": True}}, 5])
    adapter = JsonRpcAdapter(transport)
    batch = [
        {"jsonrpc": "2.0", "method": "notify", "id": None},
        {"jsonrpc": "2.0", "method": "req", "id": 1},
        {"jsonrpc": "2.0", "method": "req", "id": 2},
    ]

    responses = await adapter.send_batch_request(batch)

    assert responses == [
        {"result": {"ok": True}, "id": 1},
        {"result": 5, "id": 2},
    ]


@pytest.mark.asyncio
async def test_send_batch_request_error():
    transport = MagicMock()
    transport.send_raw = AsyncMock(side_effect=RuntimeError("boom"))
    adapter = JsonRpcAdapter(transport)

    responses = await adapter.send_batch_request([{"jsonrpc": "2.0", "id": 7}])

    assert responses == [{"error": "boom", "id": 7}]


def test_collate_batch_responses():
    adapter = JsonRpcAdapter()
    requests = [{"id": 1}, {"id": 2}, {"method": "notify", "id": None}]
    responses = [{"id": 2, "result": True}, {"id": 3, "result": False}]

    collated = adapter.collate_batch_responses(requests, responses)

    assert collated[2]["result"] is True
    assert collated[1]["error"]["message"] == "Response missing"


@pytest.mark.asyncio
async def test_get_tools_handles_non_dict_response():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value=["not-a-dict"])
    adapter = JsonRpcAdapter(transport=transport)

    assert await adapter.get_tools() == []


@pytest.mark.asyncio
async def test_get_tools_from_nested_result():
    transport = MagicMock()
    transport.send_request = AsyncMock(
        return_value={"result": {"tools": [{"name": "x"}]}}
    )
    adapter = JsonRpcAdapter(transport=transport)

    assert await adapter.get_tools() == [{"name": "x"}]


@pytest.mark.asyncio
async def test_send_batch_request_normalizes_responses():
    transport = MagicMock()
    transport.send_raw = AsyncMock(side_effect=["ok", {"result": "done"}])
    adapter = JsonRpcAdapter(transport=transport)

    batch = [
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        {"jsonrpc": "2.0", "method": "ping", "id": 2},
    ]
    responses = await adapter.send_batch_request(batch)

    assert responses[0]["id"] == 1
    assert responses[0]["result"] == "ok"


def test_collate_batch_responses_handles_missing_and_unmatched():
    adapter = JsonRpcAdapter()
    requests = [{"id": 1}, {"id": 2}]
    responses = [{"id": 99, "result": "extra"}]

    collated = adapter.collate_batch_responses(requests, responses)

    assert collated[1]["error"]["message"] == "Response missing"
    assert collated[2]["error"]["message"] == "Response missing"
