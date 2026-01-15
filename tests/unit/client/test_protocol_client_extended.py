"""Extended tests for protocol_client.py to improve coverage."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from mcp_fuzzer.client.protocol_client import ProtocolClient


@pytest.fixture
def mock_transport():
    """Create a mock transport with all necessary methods."""
    transport = MagicMock()
    transport.send_request = AsyncMock(return_value={"result": "ok"})
    transport.send_notification = AsyncMock(return_value=None)
    return transport


@pytest.fixture
def mock_safety():
    """Create a mock safety system."""
    safety = MagicMock()
    safety.should_skip_protocol_message = MagicMock(return_value=False)
    safety.sanitize_protocol_message = MagicMock(side_effect=lambda m: m)
    return safety


@pytest.fixture
def client(mock_transport, mock_safety):
    """Create a ProtocolClient with mocked dependencies."""
    return ProtocolClient(transport=mock_transport, safety_system=mock_safety)


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
    async def test_dispatch_cancel_notification(self, client):
        """Test dispatching CancelNotification."""
        result = await client._send_protocol_request(
            "CancelNotification", {"params": {"requestId": "req1"}}
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

    @pytest.mark.asyncio
    async def test_get_protocol_types_returns_list(self, client):
        """Test getting protocol types returns a list."""
        with patch(
            "mcp_fuzzer.client.protocol_client.ProtocolExecutor"
        ) as mock_executor:
            mock_executor.PROTOCOL_TYPES = ["InitializeRequest", "ListResourcesRequest"]
            result = await client._get_protocol_types()
            assert result == ["InitializeRequest", "ListResourcesRequest"]

    @pytest.mark.asyncio
    async def test_get_protocol_types_handles_missing_attr(self, client):
        """Test getting protocol types handles missing attribute."""
        with patch(
            "mcp_fuzzer.client.protocol_client.ProtocolExecutor"
        ) as mock_executor:
            del mock_executor.PROTOCOL_TYPES
            result = await client._get_protocol_types()
            assert result == []

    @pytest.mark.asyncio
    async def test_get_protocol_types_handles_exception(self, client):
        """Test getting protocol types handles exceptions."""
        with patch(
            "mcp_fuzzer.client.protocol_client.ProtocolExecutor",
            side_effect=Exception("fail"),
        ):
            result = await client._get_protocol_types()
            assert result == []


class TestFuzzAllProtocolTypes:
    """Test fuzz_all_protocol_types method."""

    @pytest.mark.asyncio
    async def test_fuzz_all_returns_empty_when_no_types(self, client):
        """Test fuzzing all types returns empty when no protocol types."""
        client._get_protocol_types = AsyncMock(return_value=[])
        result = await client.fuzz_all_protocol_types()
        assert result == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_handles_exception(self, client):
        """Test fuzzing all types handles exceptions gracefully."""
        client._get_protocol_types = AsyncMock(side_effect=Exception("boom"))
        result = await client.fuzz_all_protocol_types()
        assert result == {}

    @pytest.mark.asyncio
    async def test_fuzz_all_runs_for_each_type(self, client):
        """Test fuzzing all types runs for each protocol type."""
        client._get_protocol_types = AsyncMock(return_value=["InitializeRequest"])
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
