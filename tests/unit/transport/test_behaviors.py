#!/usr/bin/env python3
"""
Unit tests for transport behaviors/mixins.
"""

import itertools
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_fuzzer.exceptions import PayloadValidationError, TransportError, NetworkError
from mcp_fuzzer.transport.interfaces.behaviors import (
    DriverBaseBehavior,
    HttpClientBehavior,
    ResponseParserBehavior,
    LifecycleBehavior,
)
from mcp_fuzzer.transport.interfaces.states import DriverState


class DummyDriver(DriverBaseBehavior):
    pass


class DummyHttp(HttpClientBehavior):
    pass


class DummyParser(ResponseParserBehavior):
    pass


class DummyLifecycle(LifecycleBehavior):
    pass


def test_create_jsonrpc_request_invalid_method():
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._create_jsonrpc_request("", {})


def test_validate_jsonrpc_payload_strict_missing_id():
    driver = DummyDriver()
    payload = {"jsonrpc": "2.0", "method": "ping"}
    with pytest.raises(PayloadValidationError):
        driver._validate_jsonrpc_payload(payload, strict=True)


def test_validate_jsonrpc_payload_response_error_missing_fields():
    driver = DummyDriver()
    payload = {"jsonrpc": "2.0", "error": {"message": "bad"}, "id": 1}
    with pytest.raises(PayloadValidationError):
        driver._validate_jsonrpc_payload(payload)


def test_extract_result_from_response_error_raises():
    driver = DummyDriver()
    with pytest.raises(TransportError):
        driver._extract_result_from_response({"error": "boom"})


def test_extract_result_from_response_normalizes():
    driver = DummyDriver()
    assert driver._extract_result_from_response("ok") == {"result": "ok"}
    assert driver._extract_result_from_response("ok", normalize_non_dict=False) == "ok"


def test_validate_payload_serializable():
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._validate_payload_serializable({"x": object()})


def test_validate_network_request_blocks(monkeypatch):
    """Test _validate_network_request raises NetworkError when host not allowed."""
    driver = DummyHttp()

    def deny_all(url, **kwargs):
        return False

    monkeypatch.setitem(
        DummyHttp._validate_network_request.__globals__,
        "safety_policy",
        SimpleNamespace(is_host_allowed=deny_all),
    )

    # Test that the method raises NetworkError
    with pytest.raises(NetworkError):
        driver._validate_network_request("http://example.com")


def test_handle_http_response_error():
    driver = DummyHttp()
    response = httpx.Response(
        400, text="nope", request=httpx.Request("GET", "http://x")
    )
    with pytest.raises(NetworkError):
        driver._handle_http_response_error(response)


def test_parse_http_response_json_fallback_sse():
    driver = DummyHttp()

    class FakeResponse:
        def json(self):
            raise json.JSONDecodeError("bad", "x", 0)

        text = 'data: {"result": {"ok": true}}'

    result = driver._parse_http_response_json(FakeResponse())

    assert result == {"ok": True}


def test_parse_http_response_json_no_fallback():
    driver = DummyHttp()

    class FakeResponse:
        def json(self):
            raise json.JSONDecodeError("bad", "x", 0)

        text = "not json"

    with pytest.raises(TransportError):
        driver._parse_http_response_json(FakeResponse(), fallback_to_sse=False)


def test_parse_sse_event_and_streaming():
    parser = DummyParser()
    event = 'event: message\ndata: {"a": 1}\n\n'
    assert parser.parse_sse_event(event) == {"a": 1}

    lines = ['data: {"a": 1}', "", 'data: {"b": 2}', ""]
    assert list(parser.parse_streaming_response(lines)) == [{"a": 1}, {"b": 2}]


def test_parse_streaming_response_bad_json():
    parser = DummyParser()
    lines = ["data: {bad}", ""]
    assert list(parser.parse_streaming_response(lines)) == []


def test_lifecycle_state_changes(monkeypatch):
    lifecycle = DummyLifecycle()

    times = itertools.count(start=100.0, step=5.0)
    monkeypatch.setattr(
        "mcp_fuzzer.transport.interfaces.behaviors.time.time",
        lambda: next(times),
    )

    assert lifecycle.connection_state == DriverState.INIT
    lifecycle._set_connection_state(DriverState.CONNECTED)
    assert lifecycle.is_connected() is True
    lifecycle._set_connection_state(DriverState.CLOSED)
    assert lifecycle.is_closed() is True
    assert lifecycle.connection_duration == 5.0


def test_touch_activity_callbacks():
    lifecycle = DummyLifecycle()
    called = []
    lifecycle.register_activity_callback(lambda ts: called.append(ts))
    lifecycle._touch_activity()
    assert len(called) == 1


def test_create_jsonrpc_notification_invalid_method():
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._create_jsonrpc_notification("")


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "1.0", "method": "ping"},
        {"jsonrpc": "2.0", "method": "", "id": 1},
        {"jsonrpc": "2.0", "method": "ping", "params": "bad"},
        {"jsonrpc": "2.0", "method": "ping", "id": []},
    ],
)
def test_validate_jsonrpc_payload_request_errors(payload):
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._validate_jsonrpc_payload(payload)


@pytest.mark.parametrize(
    "payload",
    [
        {"jsonrpc": "2.0", "result": 1, "error": {"code": -1, "message": "x"}},
        {"jsonrpc": "2.0", "result": 1},
        {"jsonrpc": "2.0", "error": {"code": -1, "message": "x"}, "id": []},
    ],
)
def test_validate_jsonrpc_payload_response_errors(payload):
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._validate_jsonrpc_payload(payload)


def test_validate_jsonrpc_payload_strict_requires_id():
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._validate_jsonrpc_payload(
            {"jsonrpc": "2.0", "method": "ping"}, strict=True
        )


def test_validate_payload_serializable_set():
    driver = DummyDriver()
    with pytest.raises(PayloadValidationError):
        driver._validate_payload_serializable({"data": set([1, 2])})


def test_extract_result_from_response_error():
    driver = DummyDriver()
    with pytest.raises(TransportError):
        driver._extract_result_from_response({"error": {"code": -1, "message": "x"}})


def test_extract_result_from_response_non_dict():
    driver = DummyDriver()
    assert driver._extract_result_from_response(1, normalize_non_dict=True) == {
        "result": 1
    }
    assert driver._extract_result_from_response(1, normalize_non_dict=False) == 1


def test_parse_http_response_json_non_data_line():
    driver = DummyHttp()

    class FakeResponse:
        def json(self):
            raise json.JSONDecodeError("bad", "x", 0)

        text = '{"result": {"ok": true}}'

    result = driver._parse_http_response_json(FakeResponse())
    assert result == {"ok": True}


def test_parse_http_response_json_no_valid_json():
    driver = DummyHttp()

    class FakeResponse:
        def json(self):
            raise json.JSONDecodeError("bad", "x", 0)

        text = "data: {bad}\nnot-json"

    with pytest.raises(TransportError):
        driver._parse_http_response_json(FakeResponse())


def test_parse_http_response_json_no_fallback_extra():
    driver = DummyHttp()

    class FakeResponse:
        def json(self):
            raise json.JSONDecodeError("bad", "x", 0)

        text = "data: {bad}"

    with pytest.raises(TransportError):
        driver._parse_http_response_json(FakeResponse(), fallback_to_sse=False)


def test_parse_sse_event_logs_warnings(monkeypatch):
    parser = DummyParser()
    monkeypatch.setitem(
        parser.parse_sse_event.__globals__,
        "spec_guard",
        SimpleNamespace(
            check_sse_event_text=lambda _text: [{"id": "w", "message": "x"}],
        ),
    )
    assert parser.parse_sse_event('data: {"a": 1}') == {"a": 1}


def test_parse_streaming_response_buffer_overflow():
    parser = DummyParser()
    lines = ["data: {\"a\": 1}", "data: {\"b\": 2}", ""]
    assert list(parser.parse_streaming_response(lines, buffer_size=1)) == []


def test_parse_streaming_response_flushes_remaining():
    parser = DummyParser()
    lines = ['data: {"a": 1}']
    assert list(parser.parse_streaming_response(lines)) == [{"a": 1}]


def test_validate_network_request_blocks_denied(monkeypatch):
    driver = DummyHttp()
    monkeypatch.setitem(
        driver._validate_network_request.__globals__,
        "safety_policy",
        SimpleNamespace(is_host_allowed=lambda url: False),
    )
    with pytest.raises(NetworkError):
        driver._validate_network_request("http://example.com")


def test_handle_http_response_error_raises():
    driver = DummyHttp()
    response = httpx.Response(
        400,
        request=httpx.Request("GET", "http://example.com"),
        text="bad",
    )
    with pytest.raises(NetworkError):
        driver._handle_http_response_error(response)


@pytest.mark.asyncio
async def test_lifecycle_error_state_and_callback_warning(monkeypatch):
    lifecycle = DummyLifecycle()

    def bad_callback(_ts):
        raise RuntimeError("boom")

    lifecycle.register_activity_callback(bad_callback)
    await lifecycle._lifecycle_error(RuntimeError("fail"))
    assert lifecycle.connection_state == DriverState.ERROR
