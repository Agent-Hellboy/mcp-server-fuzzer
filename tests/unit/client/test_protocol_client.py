#!/usr/bin/env python3
"""
Unit tests for ProtocolClient.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.client.protocol_client import ProtocolClient, SUPPORTED_PROTOCOL_TYPES
from mcp_fuzzer.protocol_registry import EXECUTABLE_PROTOCOL_TYPES


class DummySafety:
    def __init__(
        self,
        *,
        block: bool = False,
        sanitized: dict | None = None,
        reason: str | None = None,
    ) -> None:
        self._block = block
        self._sanitized = sanitized
        self._reason = reason

    def should_block_protocol_message(self, protocol_type, fuzz_data) -> bool:
        return self._block

    def sanitize_protocol_message(self, protocol_type, fuzz_data):
        return self._sanitized if self._sanitized is not None else fuzz_data

    def get_blocking_reason(self):
        return self._reason


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
    safety = DummySafety(block=True, reason="too_risky")
    client = ProtocolClient(transport=MagicMock(), safety_system=safety)

    result = await client._check_safety_for_protocol_message(
        "InitializeRequest", {"params": {"x": 1}}
    )

    assert result["blocked"] is True
    assert result["blocking_reason"] == "too_risky"
    assert result["data"] == {"params": {"x": 1}}


@pytest.mark.asyncio
async def test_check_safety_sanitizes_message():
    safety = DummySafety(sanitized={"params": {"x": "clean"}})
    client = ProtocolClient(transport=MagicMock(), safety_system=safety)

    result = await client._check_safety_for_protocol_message(
        "InitializeRequest", {"params": {"x": "dirty"}}
    )

    assert result["blocked"] is False
    assert result["sanitized"] is True
    assert result["data"] == {"params": {"x": "clean"}}


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_blocked():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
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
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
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

    assert result["success"] is False
    assert result.get("accepted_malformed") is True
    assert result["safety_sanitized"] is True
    assert result["spec_checks"] == [{"id": "spec"}]
    assert result["spec_scope"] == "protocol"


@pytest.mark.asyncio
async def test_process_single_protocol_fuzz_send_error():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
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
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client.protocol_mutator.mutate = AsyncMock(return_value=None)

    result = await client._process_single_protocol_fuzz("ListRootsRequest", 0, 1)

    assert result["success"] is False
    assert "No fuzz_data returned" in result["exception"]


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_empty_list():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._get_protocol_types = MagicMock(return_value=[])

    result = await client.fuzz_all_protocol_types()

    assert result == {}


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_runs():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._get_protocol_types = MagicMock(return_value=["InitializeRequest"])
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})

    result = await client.fuzz_all_protocol_types(runs_per_type=2)

    assert result == {"InitializeRequest": [{"success": True}, {"success": True}]}


@pytest.mark.asyncio
async def test_fuzz_all_protocol_types_appends_listed_results():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._get_protocol_types = MagicMock(
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
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})

    result = await client.fuzz_protocol_type("InitializeRequest", runs=3)

    assert result == [{"success": True}, {"success": True}, {"success": True}]
    assert client._process_single_protocol_fuzz.await_count == 3


@pytest.mark.asyncio
async def test_fuzz_protocol_type_appends_listed_resources():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})
    client._fuzz_listed_resources = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"uri": "u"}}}]
    )

    result = await client.fuzz_protocol_type("ReadResourceRequest", runs=2)

    assert result[-1]["fuzz_data"]["params"]["uri"] == "u"
    client._fuzz_listed_resources.assert_awaited_once()


@pytest.mark.asyncio
async def test_fuzz_protocol_type_appends_listed_prompts():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
    client._process_single_protocol_fuzz = AsyncMock(return_value={"success": True})
    client._fuzz_listed_prompts = AsyncMock(
        return_value=[{"success": True, "fuzz_data": {"params": {"name": "p"}}}]
    )

    result = await client.fuzz_protocol_type("GetPromptRequest", runs=1)

    assert result[-1]["fuzz_data"]["params"]["name"] == "p"
    client._fuzz_listed_prompts.assert_awaited_once()


@pytest.mark.asyncio
async def test_fetch_listed_tools_remembers_tools():
    transport = MagicMock()
    transport.send_request = AsyncMock(
        return_value={"result": {"tools": [{"name": "alpha"}]}}
    )
    client = ProtocolClient(transport=transport, safety_system=None)

    tools = await client._fetch_listed_tools()

    assert tools == [{"name": "alpha"}]
    assert "alpha" in client._observed_tools


def test_extract_params_handles_non_dict():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)

    assert client._extract_params({"params": {"x": 1}}) == {"x": 1}
    assert client._extract_params({"params": "nope"}) == {}
    assert client._extract_params("nope") == {}


def test_extract_list_items_handles_wrapped_results():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)

    assert client._extract_list_items({"resources": [{"uri": "u"}]}, "resources") == [
        {"uri": "u"}
    ]
    assert client._extract_list_items(
        {"result": {"prompts": [{"name": "p"}]}}, "prompts"
    ) == [{"name": "p"}]
    assert client._extract_list_items({"result": {}}, "resources") == []


@pytest.mark.asyncio
async def test_send_protocol_request_dispatch():
    client = ProtocolClient(transport=MagicMock(), safety_system=None)
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
    client = ProtocolClient(transport=transport, safety_system=None)

    result = await client._send_progress_notification({"params": {"token": "t"}})

    assert result == {"status": "notification_sent"}
    transport.send_notification.assert_called_once_with(
        "notifications/progress", {"token": "t"}
    )


@pytest.mark.asyncio
async def test_send_cancelled_notification():
    transport = MagicMock()
    transport.send_notification = AsyncMock()
    client = ProtocolClient(transport=transport, safety_system=None)

    result = await client._send_cancelled_notification({"params": {"requestId": 1}})

    assert result == {"status": "notification_sent"}
    transport.send_notification.assert_called_once_with(
        "notifications/cancelled", {"requestId": 1}
    )


@pytest.mark.asyncio
async def test_send_list_resources_request():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    client = ProtocolClient(transport=transport, safety_system=None)

    result = await client._send_list_resources_request({"params": {"cursor": "c"}})

    assert result == {"ok": True}
    transport.send_request.assert_called_once_with("resources/list", {"cursor": "c"})


@pytest.mark.asyncio
async def test_send_generic_request_missing_method():
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"ok": True})
    client = ProtocolClient(transport=transport, safety_system=None)

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

    assert result["success"] is False
    assert result.get("accepted_malformed") is True
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
    safety = DummySafety(block=True, reason="blocked")
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


@pytest.fixture
def mock_transport():
    """Create a mock transport with all necessary methods."""
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": "ok"})
    transport.send_notification = AsyncMock(return_value=None)
    return transport


@pytest.fixture
def client(mock_transport):
    """Create a ProtocolClient with mocked dependencies."""
    return ProtocolClient(transport=mock_transport, safety_system=None)


class TestProtocolRequestDispatch:
    """Test _send_protocol_request dispatch logic for all protocol types."""

    @pytest.mark.asyncio
    async def test_dispatch_progress_notification(self, client):
        """Test dispatching ProgressNotification."""
        result = await client._send_protocol_request(
            "ProgressNotification", {"params": {"progressToken": "token1"}}
        )
        assert result == {"status": "notification_sent"}
        client.transport.send_notification.assert_called()

    @pytest.mark.asyncio
    async def test_dispatch_cancelled_notification(self, client):
        """Test dispatching CancelledNotification."""
        result = await client._send_protocol_request(
            "CancelledNotification", {"params": {"requestId": "req1"}}
        )
        assert result == {"status": "notification_sent"}
        client.transport.send_notification.assert_called()

    @pytest.mark.asyncio
    async def test_dispatch_list_resources_request(self, client):
        """Test dispatching ListResourcesRequest."""
        result = await client._send_protocol_request(
            "ListResourcesRequest", {"params": {"cursor": "abc"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "resources/list",
            {"cursor": "abc"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_read_resource_request(self, client):
        """Test dispatching ReadResourceRequest."""
        result = await client._send_protocol_request(
            "ReadResourceRequest", {"params": {"uri": "file:///path"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "resources/read",
            {"uri": "file:///path"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_list_resource_templates_request(self, client):
        """Test dispatching ListResourceTemplatesRequest."""
        result = await client._send_protocol_request(
            "ListResourceTemplatesRequest", {"params": {}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "resources/templates/list",
            {},
        )

    @pytest.mark.asyncio
    async def test_dispatch_set_level_request(self, client):
        """Test dispatching SetLevelRequest."""
        result = await client._send_protocol_request(
            "SetLevelRequest", {"params": {"level": "DEBUG"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "logging/setLevel",
            {"level": "DEBUG"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_create_message_request(self, client):
        """Test dispatching CreateMessageRequest."""
        result = await client._send_protocol_request(
            "CreateMessageRequest", {"params": {"messages": []}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "sampling/createMessage",
            {"messages": []},
        )

    @pytest.mark.asyncio
    async def test_dispatch_list_prompts_request(self, client):
        """Test dispatching ListPromptsRequest."""
        result = await client._send_protocol_request(
            "ListPromptsRequest", {"params": {"cursor": "xyz"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "prompts/list",
            {"cursor": "xyz"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_get_prompt_request(self, client):
        """Test dispatching GetPromptRequest."""
        result = await client._send_protocol_request(
            "GetPromptRequest", {"params": {"name": "test_prompt"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "prompts/get",
            {"name": "test_prompt"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_list_roots_request(self, client):
        """Test dispatching ListRootsRequest."""
        result = await client._send_protocol_request(
            "ListRootsRequest", {"params": {}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with("roots/list", {})

    @pytest.mark.asyncio
    async def test_dispatch_subscribe_request(self, client):
        """Test dispatching SubscribeRequest."""
        result = await client._send_protocol_request(
            "SubscribeRequest", {"params": {"uri": "file:///sub"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "resources/subscribe",
            {"uri": "file:///sub"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_unsubscribe_request(self, client):
        """Test dispatching UnsubscribeRequest."""
        result = await client._send_protocol_request(
            "UnsubscribeRequest", {"params": {"uri": "file:///unsub"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "resources/unsubscribe",
            {"uri": "file:///unsub"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_complete_request(self, client):
        """Test dispatching CompleteRequest."""
        result = await client._send_protocol_request(
            "CompleteRequest", {"params": {"ref": "ref1", "argument": "arg1"}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "completion/complete",
            {"ref": "ref1", "argument": "arg1"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_generic_request_fallback(self, client):
        """Test dispatching unknown type falls back to generic."""
        result = await client._send_protocol_request(
            "UnknownRequestType",
            {"method": "custom/method", "params": {"foo": "bar"}},
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "custom/method",
            {"foo": "bar"},
        )

    @pytest.mark.asyncio
    async def test_dispatch_initialize_request(self, client):
        """Test dispatching InitializeRequest."""
        result = await client._send_protocol_request(
            "InitializeRequest",
            {"params": {"protocolVersion": "2024-11-05"}},
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "initialize",
            {"protocolVersion": "2024-11-05"},
        )


class TestGetProtocolTypes:
    """Test _get_protocol_types method."""

    def test_get_protocol_types_returns_list(self, client):
        """Test getting protocol types returns a list."""
        with patch(
            "mcp_fuzzer.client.protocol_client.SUPPORTED_PROTOCOL_TYPES",
            ("InitializeRequest", "ListResourcesRequest"),
        ):
            result = client._get_protocol_types()
            assert result == ["InitializeRequest", "ListResourcesRequest"]

    def test_supported_protocol_types_match_registry_order(self):
        """ProtocolClient should stay aligned with executable registry types."""
        assert SUPPORTED_PROTOCOL_TYPES == tuple(EXECUTABLE_PROTOCOL_TYPES)


class TestFuzzAllProtocolTypes:
    """Test fuzz_all_protocol_types method."""

    @pytest.mark.asyncio
    async def test_fuzz_all_returns_empty_when_no_types(self, client):
        """Test fuzzing all types returns empty when no protocol types."""
        client._get_protocol_types = MagicMock(return_value=[])
        result = await client.fuzz_all_protocol_types()
        assert result == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_handles_exception(self, client):
        """Test fuzzing all types handles exceptions gracefully."""
        client._get_protocol_types = MagicMock(side_effect=Exception("boom"))
        result = await client.fuzz_all_protocol_types()
        assert result == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_runs_for_each_type(self, client):
        """Test fuzzing all types runs for each protocol type."""
        client._get_protocol_types = MagicMock(return_value=["InitializeRequest"])
        client._process_single_protocol_fuzz = AsyncMock(
            return_value={"success": True}
        )

        result = await client.fuzz_all_protocol_types(runs_per_type=2)

        assert "InitializeRequest" in result
        assert len(result["InitializeRequest"]) == 2


class TestGenericRequest:
    """Test _send_generic_request method."""

    @pytest.mark.asyncio
    async def test_generic_request_with_valid_method(self, client):
        """Test generic request with valid method string."""
        result = await client._send_generic_request(
            {"method": "custom/endpoint", "params": {"a": 1}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with(
            "custom/endpoint",
            {"a": 1},
        )

    @pytest.mark.asyncio
    async def test_generic_request_with_empty_method(self, client):
        """Test generic request with empty method string."""
        result = await client._send_generic_request(
            {"method": "", "params": {}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with("unknown", {})

    @pytest.mark.asyncio
    async def test_generic_request_with_non_string_method(self, client):
        """Test generic request with non-string method."""
        result = await client._send_generic_request(
            {"method": 123, "params": {}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with("unknown", {})

    @pytest.mark.asyncio
    async def test_generic_request_with_none_method(self, client):
        """Test generic request with None method."""
        result = await client._send_generic_request(
            {"method": None, "params": {}}
        )
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with("unknown", {})

    @pytest.mark.asyncio
    async def test_generic_request_with_non_dict_data(self, client):
        """Test generic request with non-dict data."""
        result = await client._send_generic_request("not a dict")
        assert result == {"result": "ok"}
        client.transport.send_request.assert_called_with("unknown", {})


class TestExtractParams:
    """Test _extract_params method."""

    def test_extract_params_with_valid_dict(self, client):
        """Test extracting params from valid dict."""
        result = client._extract_params({"params": {"key": "value"}})
        assert result == {"key": "value"}

    def test_extract_params_with_missing_params(self, client):
        """Test extracting params when params key is missing."""
        result = client._extract_params({"other": "data"})
        assert result == {}

    def test_extract_params_with_non_dict_params(self, client):
        """Test extracting params when params is not a dict."""
        result = client._extract_params({"params": "not a dict"})
        assert result == {}

    def test_extract_params_with_non_dict_input(self, client):
        """Test extracting params from non-dict input."""
        result = client._extract_params("not a dict")
        assert result == {}

    def test_extract_params_with_none_input(self, client):
        """Test extracting params from None input."""
        result = client._extract_params(None)
        assert result == {}


class TestShutdown:
    """Test shutdown method."""

    @pytest.mark.asyncio
    async def test_shutdown_returns_none(self, client):
        """Test shutdown returns None."""
        result = await client.shutdown()
        assert result is None
