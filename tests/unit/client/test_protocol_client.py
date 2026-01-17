#!/usr/bin/env python3
"""
Unit tests for ProtocolClient.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.client.protocol_client import ProtocolClient


@pytest.mark.asyncio
async def test_check_safety_no_system():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)

    result = await client._check_safety_for_protocol_message(
        "InitializeRequest", {"params": {"x": 1}}
    )

    assert result == {
        "blocked": False,
        "sanitized": False,
        "blocking_reason": None,
        "data": {"params": {"x": 1}},
    }


@pytest.mark.asyncio
async def test_check_safety_blocks_message():
    safety = MagicMock()
    safety.should_block_protocol_message.return_value = True
    safety.get_blocking_reason.return_value = "too_risky"
    client = ProtocolClient(transport=MagicMock(), safety_system=safety)

    result = await client._check_safety_for_protocol_message(
        "InitializeRequest", {"params": {"x": 1}}
    )

    assert result["blocked"] is True
    assert result["blocking_reason"] == "too_risky"
    assert result["data"] == {"params": {"x": 1}}


@pytest.mark.asyncio
async def test_check_safety_sanitizes_message():
    safety = MagicMock()
    safety.should_block_protocol_message.return_value = False
    safety.sanitize_protocol_message.return_value = {"params": {"x": "clean"}}
    client = ProtocolClient(transport=MagicMock(), safety_system=safety)

    result = await client._check_safety_for_protocol_message(
        "InitializeRequest", {"params": {"x": "dirty"}}
    )

    assert result["blocked"] is False
    assert result["sanitized"] is True
    assert result["data"] == {"params": {"x": "clean"}}


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_blocked():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client.protocol_mutator.mutate = AsyncMock(return_value={"method": "x"})
    client._check_safety_for_protocol_message = AsyncMock(
        return_value={
            "blocked": True,
            "sanitized": False,
            "blocking_reason": "nope",
            "data": {"method": "x"},
        }
    )

    result = await client._process_single_protocol_fuzz("InitializeRequest", 0, 1)

    assert result["safety_blocked"] is True
    assert result["success"] is False
    assert result["result"]["error"] == "blocked_by_safety_system"


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_success_with_spec_checks():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client.protocol_mutator.mutate = AsyncMock(return_value={"method": "prompts/list"})
    client._check_safety_for_protocol_message = AsyncMock(
        return_value={
            "blocked": False,
            "sanitized": True,
            "blocking_reason": None,
            "data": {"method": "prompts/list"},
        }
    )
    client._send_protocol_request = AsyncMock(return_value={"result": {"ok": True}})

    with patch(
        "mcp_fuzzer.spec_guard.get_spec_checks_for_protocol_type",
        return_value=([{"id": "spec"}], "protocol"),
    ):
        result = await client._process_single_protocol_fuzz("ListPromptsRequest", 0, 1)

    assert result["success"] is True
    assert result["safety_sanitized"] is True
    assert result["spec_checks"] == [{"id": "spec"}]
    assert result["spec_scope"] == "protocol"


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_send_error():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client.protocol_mutator.mutate = AsyncMock(return_value={"method": "x"})
    client._check_safety_for_protocol_message = AsyncMock(
        return_value={
            "blocked": False,
            "sanitized": False,
            "blocking_reason": None,
            "data": {"method": "x"},
        }
    )
    client._send_protocol_request = AsyncMock(side_effect=RuntimeError("boom"))

    result = await client._process_single_protocol_fuzz("ListRootsRequest", 0, 1)

    assert result["success"] is False
    assert result["result"]["error"] == "boom"


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_mutator_none():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client.protocol_mutator.mutate = AsyncMock(return_value=None)

    result = await client._process_single_protocol_fuzz("ListRootsRequest", 0, 1)

    assert result["success"] is False
    assert "No fuzz_data returned" in result["exception"]


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_empty_list():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._get_protocol_types = AsyncMock(return_value=[])

    result = await client.fuzz_all_protocol_types()

    assert result == {}


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_runs():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._get_protocol_types = AsyncMock(return_value=["InitializeRequest"])
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})

    result = await client.fuzz_all_protocol_types(runs_per_type=2)

    assert result == {"InitializeRequest": [{"success": True}, {"success": True}]}


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_appends_listed_results():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._get_protocol_types = AsyncMock(
        return_value=["ReadResourceRequest", "GetPromptRequest"]
    )
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})
    client._fuzz_listed_resources = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"uri": "u"}}}]
    )
    client._fuzz_listed_prompts = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"name": "p"}}}]
    )

    result = await client.fuzz_all_protocol_types(runs_per_type=1)

    assert result["ReadResourceRequest"][-1]["fuzz_data"]["params"]["uri"] == "u"
    assert result["GetPromptRequest"][-1]["fuzz_data"]["params"]["name"] == "p"
    client._fuzz_listed_resources.assert_awaited_once()
    client._fuzz_listed_prompts.assert_awaited_once()


@pytest.mark.asyncio
async def test_fuzz_protocol_type_collects_runs():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})

    result = await client.fuzz_protocol_type("InitializeRequest", runs=3)

    assert result == [{"success": True}, {"success": True}, {"success": True}]
    assert client._process_single_protocol_fuzz.await_count == 3


@pytest.mark.asyncio
async def test_fuzz_protocol_type_appends_listed_resources():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})
    client._fuzz_listed_resources = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"uri": "u"}}}]
    )

    result = await client.fuzz_protocol_type("ReadResourceRequest", runs=2)

    assert result[-1]["fuzz_data"]["params"]["uri"] == "u"
    client._fuzz_listed_resources.assert_awaited_once()


@pytest.mark.asyncio
async def test_fuzz_protocol_type_appends_listed_prompts():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})
    client._fuzz_listed_prompts = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"name": "p"}}}]
    )

    result = await client.fuzz_protocol_type("GetPromptRequest", runs=1)

    assert result[-1]["fuzz_data"]["params"]["name"] == "p"
    client._fuzz_listed_prompts.assert_awaited_once()


def test_extract_params_handles_non_dict():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())

    assert client._extract_params({"params": {"x": 1}}) == {"x": 1}
    assert client._extract_params({"params": "nope"}) == {}
    assert client._extract_params("nope") == {}


def test_extract_list_items_handles_wrapped_results():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())

    assert client._extract_list_items({"resources": [{"uri": "u"}]}, "resources") == [
        {"uri": "u"}
    ]
    assert client._extract_list_items(
        {"result": {"prompts": [{"name": "p"}]}}, "prompts"
    ) == [{"name": "p"}]
    assert client._extract_list_items({"result": {}}, "resources") == []


@pytest.mark.asyncio
async def test_send_protocol_request_dispatch():
    client = ProtocolClient(transport=MagicMock(), safety_system=MagicMock())
    client._send_initialize_request = AsyncMock(return_value={"ok": True})

    result = await client._send_protocol_request(
        "InitializeRequest", {"params": {"x": 1}}
    )

    assert result == {"ok": True}
    client._send_initialize_request.assert_called_once()


@pytest.mark.asyncio
async def test_send_progress_notification():
    transport = MagicMock()
    transport.send_notification = AsyncMock()
    client = ProtocolClient(transport=transport, safety_system=MagicMock())

    result = await client._send_progress_notification({"params": {"token": "t"}})

    assert result == {"status": "notification_sent"}
    transport.send_notification.assert_called_once_with(
        "notifications/progress", {"token": "t"}
    )


@pytest.mark.asyncio
async def test_send_cancel_notification():
    transport = MagicMock()
    transport.send_notification = AsyncMock()
    client = ProtocolClient(transport=transport, safety_system=MagicMock())

    result = await client._send_cancel_notification({"params": {"requestId": 1}})

    assert result == {"status": "notification_sent"}
    transport.send_notification.assert_called_once_with(
        "notifications/cancelled", {"requestId": 1}
    )


@pytest.mark.asyncio
async def test_send_list_resources_request():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    client = ProtocolClient(transport=transport, safety_system=MagicMock())

    result = await client._send_list_resources_request({"params": {"cursor": "c"}})

    assert result == {"ok": True}
    transport.send_request.assert_called_once_with("resources/list", {"cursor": "c"})


@pytest.mark.asyncio
async def test_send_generic_request_missing_method():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    client = ProtocolClient(transport=transport, safety_system=MagicMock())

    result = await client._send_generic_request({"params": {"x": 1}})

    assert result == {"ok": True}
    transport.send_request.assert_called_once_with("unknown", {"x": 1})


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_preview_fallback(monkeypatch):
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": {"ok": True}})
    client = ProtocolClient(transport=transport, safety_system=None)

    monkeypatch.setattr(
        client.protocol_mutator,
        "mutate",
        AsyncMock(return_value={"method": "ping", "params": {"bad": object()}}),
    )
    monkeypatch.setattr(client, "_send_protocol_request", AsyncMock(return_value={}))

    result = await client._process_single_protocol_fuzz("PingRequest", 0, 1)

    assert result["success"] is True
    assert result["result"]["error"] is None


def test_extract_params_non_dict():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    assert client._extract_params(["not-a-dict"]) == {}


def test_extract_list_items_inner_result():
    result = {"result": {"resources": [{"uri": "x"}]}}
    assert ProtocolClient._extract_list_items(result, "resources") == [{"uri": "x"}]


@pytest.mark.asyncio
async def test_fetch_listed_resources_handles_error():
    transport = MagicMock()
    transport.send_request = AsyncMock(side_effect=RuntimeError("boom"))
    client = ProtocolClient(transport=transport, safety_system=None)

    assert await client._fetch_listed_resources() == []


@pytest.mark.asyncio
async def test_process_protocol_request_blocked():
    safety = SimpleNamespace(
        should_block_protocol_message=lambda *_args, **_kwargs: True,
        get_blocking_reason=lambda: "blocked",
    )
    transport = MagicMock()
    client = ProtocolClient(transport=transport, safety_system=safety)

    result = await client._process_protocol_request(
        "ReadResourceRequest", "resources/read", {"uri": "x"}, "resource:x"
    )

    assert result["safety_blocked"] is True
    assert result["success"] is False
    assert result["result"]["error"] == "blocked_by_safety_system"


@pytest.mark.asyncio
async def test_process_protocol_request_send_error(monkeypatch):
    transport = MagicMock()
    client = ProtocolClient(transport=transport, safety_system=None)

    async def _fail_send(*_args, **_kwargs):
        raise RuntimeError("send failed")

    monkeypatch.setattr(client, "_send_protocol_request", _fail_send)

    result = await client._process_protocol_request(
        "ReadResourceRequest", "resources/read", {"uri": "x"}, "resource:x"
    )

    assert result["success"] is False
    assert result["result"]["error"] == "send failed"


@pytest.mark.asyncio
async def test_fuzz_listed_resources_filters_invalid(monkeypatch):
    transport = MagicMock()
    transport.send_request = AsyncMock(
        return_value={"resources": [{"uri": "ok"}, {"uri": ""}, {"foo": "bar"}]}
    )
    client = ProtocolClient(transport=transport, safety_system=None)

    monkeypatch.setattr(client, "_process_protocol_request", AsyncMock(return_value={}))
    results = await client._fuzz_listed_resources()

    assert len(results) == 1


@pytest.mark.asyncio
async def test_fuzz_listed_prompts_filters_invalid(monkeypatch):
    transport = MagicMock()
    transport.send_request = AsyncMock(
        return_value={"prompts": [{"name": "ok"}, {"name": ""}, {"foo": "bar"}]}
    )
    client = ProtocolClient(transport=transport, safety_system=None)

    monkeypatch.setattr(client, "_process_protocol_request", AsyncMock(return_value={}))
    results = await client._fuzz_listed_prompts()

    assert len(results) == 1
