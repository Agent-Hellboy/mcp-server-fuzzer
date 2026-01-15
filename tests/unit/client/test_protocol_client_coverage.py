import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from mcp_fuzzer.client.protocol_client import ProtocolClient


@pytest.fixture
def client():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    transport.send_notification = AsyncMock(return_value=None)
    return ProtocolClient(transport=transport, safety_system=MagicMock())

@pytest.mark.asyncio
async def test_send_initialize_request(client):
    result = await client._send_initialize_request(
        {"params": {"protocolVersion": "2024-11-05"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "initialize",
        {"protocolVersion": "2024-11-05"},
    )

@pytest.mark.asyncio
async def test_send_read_resource_request(client):
    result = await client._send_read_resource_request(
        {"params": {"uri": "file:///tmp"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "resources/read",
        {"uri": "file:///tmp"},
    )

@pytest.mark.asyncio
async def test_send_list_resource_templates_request(client):
    result = await client._send_list_resource_templates_request(
        {"params": {"cursor": "x"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "resources/templates/list",
        {"cursor": "x"},
    )

@pytest.mark.asyncio
async def test_send_set_level_request(client):
    result = await client._send_set_level_request(
        {"params": {"level": "INFO"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "logging/setLevel",
        {"level": "INFO"},
    )

@pytest.mark.asyncio
async def test_send_create_message_request(client):
    result = await client._send_create_message_request(
        {"params": {"messages": []}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "sampling/createMessage",
        {"messages": []},
    )

@pytest.mark.asyncio
async def test_send_list_prompts_request(client):
    result = await client._send_list_prompts_request(
        {"params": {"cursor": "p"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "prompts/list",
        {"cursor": "p"},
    )

@pytest.mark.asyncio
async def test_send_get_prompt_request(client):
    result = await client._send_get_prompt_request(
        {"params": {"name": "foo", "arguments": {}}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "prompts/get",
        {"name": "foo", "arguments": {}},
    )

@pytest.mark.asyncio
async def test_send_list_roots_request(client):
    result = await client._send_list_roots_request({"params": {}})
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with("roots/list", {})

@pytest.mark.asyncio
async def test_send_subscribe_request(client):
    result = await client._send_subscribe_request({"params": {"uri": "file://"}})
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "resources/subscribe",
        {"uri": "file://"},
    )

@pytest.mark.asyncio
async def test_send_unsubscribe_request(client):
    result = await client._send_unsubscribe_request({"params": {"uri": "file://"}})
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "resources/unsubscribe",
        {"uri": "file://"},
    )

@pytest.mark.asyncio
async def test_send_complete_request(client):
    result = await client._send_complete_request(
        {"params": {"ref": "x", "argument": "y"}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "completion/complete",
        {"ref": "x", "argument": "y"},
    )

@pytest.mark.asyncio
async def test_send_generic_request_with_method(client):
    result = await client._send_generic_request(
        {"method": "custom/method", "params": {"a": 1}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with(
        "custom/method",
        {"a": 1},
    )

@pytest.mark.asyncio
async def test_send_generic_request_empty_method(client):
    result = await client._send_generic_request(
        {"method": "", "params": {"a": 1}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with("unknown", {"a": 1})

@pytest.mark.asyncio
async def test_send_generic_request_non_string_method(client):
    result = await client._send_generic_request(
        {"method": 123, "params": {"a": 1}}
    )
    assert result == {"ok": True}
    client.transport.send_request.assert_called_with("unknown", {"a": 1})

@pytest.mark.asyncio
async def test_get_protocol_types_exception():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    with patch(
        "mcp_fuzzer.client.protocol_client.ProtocolExecutor",
        side_effect=Exception("boom"),
    ):
        result = await client._get_protocol_types()
        assert result == []

@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_exception():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._get_protocol_types = AsyncMock(side_effect=Exception("boom"))
    result = await client.fuzz_all_protocol_types()
    assert result == {}

@pytest.mark.asyncio
async def test_shutdown(client):
    result = await client.shutdown()
    assert result is None
