from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from mcp_fuzzer.transport.interfaces.rpc_adapter import JsonRpcAdapter


@pytest.mark.asyncio
async def test_rpc_adapter_convenience_methods():
    transport = SimpleNamespace(send_request=AsyncMock(return_value={"ok": True}))
    adapter = JsonRpcAdapter(transport)

    await adapter.ping()
    await adapter.set_logging_level("info")
    await adapter.list_resources()
    await adapter.list_resource_templates()
    await adapter.read_resource("resource://1")
    await adapter.subscribe_resource("resource://1")
    await adapter.unsubscribe_resource("resource://1")
    await adapter.list_prompts()
    await adapter.get_prompt("prompt")

    expected_calls = [
        ("ping", None),
        ("logging/setLevel", {"level": "info"}),
        ("resources/list", None),
        ("resources/templates/list", None),
        ("resources/read", {"uri": "resource://1"}),
        ("resources/subscribe", {"uri": "resource://1"}),
        ("resources/unsubscribe", {"uri": "resource://1"}),
        ("prompts/list", None),
        ("prompts/get", {"name": "prompt", "arguments": {}}),
    ]
    actual_calls = [
        (call.args[0], call.args[1] if len(call.args) > 1 else None)
        for call in transport.send_request.await_args_list
    ]
    for expected in expected_calls:
        assert expected in actual_calls


@pytest.mark.asyncio
async def test_rpc_adapter_complete_argument_shapes():
    transport = SimpleNamespace(send_request=AsyncMock(return_value={"ok": True}))
    adapter = JsonRpcAdapter(transport)

    await adapter.complete("prompt", {})
    await adapter.complete("prompt", {"a": "1"})
    await adapter.complete("prompt", {"a": "1", "b": "2"})

    calls = transport.send_request.await_args_list
    assert calls[0].args[1]["argument"] == {"name": "query", "value": ""}
    assert calls[1].args[1]["argument"] == {"name": "a", "value": "1"}
    assert isinstance(calls[2].args[1]["argument"], list)


@pytest.mark.asyncio
async def test_rpc_adapter_send_batch_request_normalizes():
    async def _send_raw(payload):
        if payload.get("id") is None:
            return None
        return "ok"

    transport = SimpleNamespace(send_raw=AsyncMock(side_effect=_send_raw))
    adapter = JsonRpcAdapter(transport)

    batch = [
        {"jsonrpc": "2.0", "method": "ping", "id": 1},
        {"jsonrpc": "2.0", "method": "notify"},
    ]

    responses = await adapter.send_batch_request(batch)

    assert responses == [{"result": "ok", "id": 1}]
