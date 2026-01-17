import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from mcp_fuzzer.exceptions import NetworkError, PayloadValidationError, TransportError
from mcp_fuzzer.transport.interfaces.behaviors import (
    HttpClientBehavior,
    LifecycleBehavior,
    ResponseParserBehavior,
)


class DummyBehavior(LifecycleBehavior, ResponseParserBehavior, HttpClientBehavior):
    def __init__(self):
        super().__init__()


def test_validate_jsonrpc_payload_errors():
    dummy = DummyBehavior()

    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload("not-a-dict")
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload({"jsonrpc": "1.0"})
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload(
            {"jsonrpc": "2.0", "method": "ping"}, strict=True
        )
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload({"jsonrpc": "2.0", "result": 1, "error": {}})
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload({"jsonrpc": "2.0", "result": 1})
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": "x"}}
        )
    with pytest.raises(PayloadValidationError):
        dummy._validate_jsonrpc_payload(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": 2}}
        )


def test_create_jsonrpc_request_with_id():
    dummy = DummyBehavior()

    payload = dummy._create_jsonrpc_request("ping", {"ok": True}, request_id=1)

    assert payload["id"] == 1


def test_validate_jsonrpc_payload_error_fields_ok():
    dummy = DummyBehavior()

    dummy._validate_jsonrpc_payload(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "bad"}}
    )


def test_log_error_and_raise_without_data():
    dummy = DummyBehavior()

    with pytest.raises(TransportError):
        dummy._log_error_and_raise("boom")


def test_handle_http_response_error_raises_network_error():
    dummy = DummyBehavior()
    request = httpx.Request("GET", "http://example.com")
    response = httpx.Response(400, request=request, text="bad")

    with pytest.raises(NetworkError):
        dummy._handle_http_response_error(response)


def test_parse_http_response_json_fallback():
    dummy = DummyBehavior()

    class BadResponse:
        text = 'data: {"result": {"ok": true}}'

        def json(self):
            raise json.JSONDecodeError("bad", "doc", 1)

    result = dummy._parse_http_response_json(BadResponse())
    assert result == {"ok": True}

    class BadResponseNoFallback:
        text = "nope"

        def json(self):
            raise json.JSONDecodeError("bad", "doc", 1)

    with pytest.raises(TransportError):
        dummy._parse_http_response_json(BadResponseNoFallback(), fallback_to_sse=False)


def test_parse_http_response_json_non_data_line():
    dummy = DummyBehavior()

    class FakeResponse:
        text = '{"result": {"ok": true}}'

        def json(self):
            raise json.JSONDecodeError("bad", "doc", 1)

    assert dummy._parse_http_response_json(FakeResponse()) == {"ok": True}


def test_parse_sse_event_warns(monkeypatch):
    dummy = DummyBehavior()
    warnings = []

    def _warn(*args, **_kwargs):
        warnings.append(args)

    dummy._logger = SimpleNamespace(warning=_warn)
    monkeypatch.setitem(
        dummy.parse_sse_event.__globals__,
        "spec_guard",
        SimpleNamespace(
            check_sse_event_text=lambda _text: [{"id": "warn", "message": "bad"}]
        ),
    )

    parsed = dummy.parse_sse_event('data: {"ok": true}')

    assert parsed == {"ok": True}
    assert warnings


def test_parse_sse_event_without_data():
    dummy = DummyBehavior()

    assert dummy.parse_sse_event("event: ping") is None


def test_parse_streaming_response_buffer_reset():
    dummy = DummyBehavior()
    dummy._logger = MagicMock()

    lines = ["data: {\"ok\": 1}", "data: {\"ok\": 2}", ""]
    results = list(dummy.parse_streaming_response(lines, buffer_size=1))

    assert results == []
    dummy._logger.warning.assert_called()


def test_parse_streaming_response_logs_bad_json():
    dummy = DummyBehavior()
    dummy._logger = MagicMock()

    lines = ["data: {bad}", ""]

    assert list(dummy.parse_streaming_response(lines)) == []
    dummy._logger.error.assert_called()


@pytest.mark.asyncio
async def test_lifecycle_state_transitions_and_callbacks():
    dummy = DummyBehavior()
    dummy._logger = MagicMock()

    def _bad_callback(_ts):
        raise RuntimeError("boom")

    dummy.register_activity_callback(_bad_callback)
    dummy._touch_activity()

    assert dummy.connection_duration is None
    await dummy._lifecycle_connect()
    await dummy._lifecycle_connected()
    assert dummy.is_connected() is True
    await dummy._lifecycle_disconnect()
    await dummy._lifecycle_closed()
    assert dummy.is_closed() is True
    await dummy._lifecycle_error(RuntimeError("fail"))


def test_time_since_last_activity():
    dummy = DummyBehavior()

    assert dummy.time_since_last_activity() >= 0
