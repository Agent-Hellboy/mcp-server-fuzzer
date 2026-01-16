#!/usr/bin/env python3
"""
Unit tests for TransportCoordinator.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.exceptions import TransportError
from mcp_fuzzer.transport.controller.coordinator import TransportCoordinator


@pytest.mark.asyncio
async def test_build_driver_tracks_transport_and_sets_helper():
    coordinator = TransportCoordinator()
    coordinator._jsonrpc_helper = MagicMock()
    transport = MagicMock()

    with patch(
        "mcp_fuzzer.transport.catalog.builder.build_driver",
        return_value=transport,
    ):
        result = await coordinator.build_driver(
            "stdio", endpoint="x", transport_id="t1"
        )

    assert result is transport
    assert coordinator.get_active_transports()["t1"] is transport
    coordinator._jsonrpc_helper.set_transport.assert_called_once_with(transport)


@pytest.mark.asyncio
async def test_build_driver_error_raises_transport_error():
    coordinator = TransportCoordinator()

    with patch(
        "mcp_fuzzer.transport.catalog.builder.build_driver",
        side_effect=RuntimeError("boom"),
    ):
        with pytest.raises(TransportError):
            await coordinator.build_driver("stdio")


@pytest.mark.asyncio
async def test_connect_adds_transport():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.connect = AsyncMock()

    await coordinator.connect(transport, transport_id="t1")

    assert coordinator.get_active_transports()["t1"] is transport


@pytest.mark.asyncio
async def test_connect_error_raises_transport_error():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.connect = AsyncMock(side_effect=RuntimeError("boom"))

    with pytest.raises(TransportError):
        await coordinator.connect(transport, transport_id="t1")

    assert coordinator.get_active_transports() == {}


@pytest.mark.asyncio
async def test_disconnect_removes_transport():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.disconnect = AsyncMock()
    coordinator._active_transports["t1"] = transport

    await coordinator.disconnect(transport, transport_id="t1")

    assert coordinator.get_active_transports() == {}


@pytest.mark.asyncio
async def test_disconnect_error_does_not_raise():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.disconnect = AsyncMock(side_effect=RuntimeError("boom"))
    coordinator._active_transports["t1"] = transport

    await coordinator.disconnect(transport, transport_id="t1")

    assert coordinator.get_active_transports()["t1"] is transport


@pytest.mark.asyncio
async def test_send_request_error_raises():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.send_request = AsyncMock(side_effect=RuntimeError("boom"))

    with pytest.raises(TransportError):
        await coordinator.send_request(transport, "x", params={})


@pytest.mark.asyncio
async def test_send_request_success():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})

    result = await coordinator.send_request(transport, "x", params={"a": 1})

    assert result == {"ok": True}
    transport.send_request.assert_called_once_with("x", {"a": 1})


@pytest.mark.asyncio
async def test_send_raw_error_raises():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.send_raw = AsyncMock(side_effect=RuntimeError("boom"))

    with pytest.raises(TransportError):
        await coordinator.send_raw(transport, {"x": 1})


@pytest.mark.asyncio
async def test_send_raw_success():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    transport.send_raw = AsyncMock(return_value={"ok": True})

    result = await coordinator.send_raw(transport, {"x": 1})

    assert result == {"ok": True}
    transport.send_raw.assert_called_once_with({"x": 1})


@pytest.mark.asyncio
async def test_get_tools_uses_jsonrpc_helper():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    coordinator._jsonrpc_helper = MagicMock()
    coordinator._jsonrpc_helper.get_tools = AsyncMock(return_value=[{"name": "a"}])

    result = await coordinator.get_tools(transport)

    assert result == [{"name": "a"}]
    coordinator._jsonrpc_helper.set_transport.assert_called_once_with(transport)


@pytest.mark.asyncio
async def test_call_tool_uses_jsonrpc_helper():
    coordinator = TransportCoordinator()
    transport = MagicMock()
    coordinator._jsonrpc_helper = MagicMock()
    coordinator._jsonrpc_helper.call_tool = AsyncMock(return_value={"ok": True})

    result = await coordinator.call_tool(transport, "alpha", {"x": 1})

    assert result == {"ok": True}
    coordinator._jsonrpc_helper.set_transport.assert_called_once_with(transport)


def test_list_available_transports(monkeypatch):
    coordinator = TransportCoordinator()

    expected = {"stdio": {"name": "stdio"}}
    fake_catalog = SimpleNamespace(list_transports=lambda include_custom=True: expected)
    monkeypatch.setitem(
        coordinator.list_available_transports.__globals__,
        "driver_catalog",
        fake_catalog,
    )

    result = coordinator.list_available_transports()

    assert result == expected


@pytest.mark.asyncio
async def test_cleanup_handles_disconnect_errors():
    coordinator = TransportCoordinator()
    coordinator.disconnect = AsyncMock(side_effect=RuntimeError("boom"))
    coordinator._active_transports["t1"] = MagicMock()

    await coordinator.cleanup()
    coordinator.disconnect.assert_called_once()
    assert coordinator._active_transports == {}
