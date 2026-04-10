"""Exercise ServerRequestHandler helpers for coverage."""

import pytest

from mcp_fuzzer.transport.interfaces import server_requests as sr
from mcp_fuzzer.transport.methods import (
    ELICITATION_CREATE,
    NOTIFY_TASKS_STATUS,
    ROOTS_LIST,
)


class _DummyUUID:
    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.text

    @property
    def hex(self) -> str:
        return self.text.replace("-", "")


@pytest.fixture(autouse=True)
def _stable_time_and_uuid(monkeypatch):
    monkeypatch.setattr(sr, "_utc_now", lambda: "2024-01-01T00:00:00Z")
    monkeypatch.setattr(sr.uuid, "uuid4", lambda: _DummyUUID("1234abcd"))


def test_is_server_request_and_notification_flags():
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": ROOTS_LIST,
    }
    notify = {"jsonrpc": "2.0", "method": NOTIFY_TASKS_STATUS}
    assert sr.is_server_request(request)
    assert not sr.is_server_request(notify)
    assert sr.is_server_notification(notify)
    assert not sr.is_server_notification(request)


def test_sampling_result_uses_tool_when_provided():
    result = sr.build_sampling_create_message_result(
        {"tools": [{"name": "hammer"}], "toolChoice": {"mode": "auto"}}
    )
    assert result["stopReason"] == "toolUse"
    assert isinstance(result["content"], list)
    assert result["content"][0]["name"] == "hammer"
    assert result["content"][0]["id"].startswith("tool-use-1234abcd")


def test_task_manager_task_aware_and_cancel():
    mgr = sr.TaskManager()
    params = {"task": {"ttl": 120000}}
    response = mgr.task_aware_result(
        request_id=99,
        params=params,
        origin_method="sampling/createMessage",
        final_result={"ok": True},
    )
    task = response["result"]["task"]
    task_id = task["taskId"]
    assert task["status"] == "completed"
    assert mgr.tasks[task_id].origin_method == "sampling/createMessage"
    assert mgr.tasks[task_id].result == {"ok": True}

    cancelled = mgr.cancel_response(request_id=5, task_id=task_id)
    assert cancelled["result"]["status"] == "cancelled"
    assert mgr.tasks[task_id].error["code"] == sr.JSONRPC_CANCELLED


def test_task_manager_get_and_result_errors():
    mgr = sr.TaskManager()
    err = mgr.get_response(request_id=1, task_id=None)
    assert err["error"]["code"] == sr.JSONRPC_INVALID_PARAMS
    err = mgr.result_response(request_id=2, task_id="missing")
    assert err["error"]["code"] == sr.JSONRPC_INVALID_PARAMS


def test_handler_notification_updates_status_and_logs():
    handler = sr.ServerRequestHandler()
    created = handler.tasks._create_task(
        origin_method="tools/call", ttl=None, result={"ok": True}
    )
    payload = {
        "jsonrpc": "2.0",
        "method": NOTIFY_TASKS_STATUS,
        "params": {"taskId": created["taskId"], "status": "running"},
    }
    assert handler.handle_notification(payload)
    assert handler.tasks.tasks[created["taskId"]].task["status"] == "running"
    assert handler.notifications.methods[-1] == NOTIFY_TASKS_STATUS


def test_handle_request_roots_and_unknown():
    handler = sr.ServerRequestHandler(roots=[{"name": "x", "uri": "file:///tmp"}])
    payload = {"jsonrpc": "2.0", "id": 7, "method": ROOTS_LIST}
    result = handler.handle_request(payload)
    assert result["result"]["roots"][0]["name"] == "x"
    assert handler.handle_request({"jsonrpc": "2.0", "id": 1, "method": "nope"}) is None


def test_elicitation_create_tracks_pending_and_creates_task():
    handler = sr.ServerRequestHandler()
    payload = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": ELICITATION_CREATE,
        "params": {
            "elicitationId": "elic-1",
            "task": {"ttl": 1},
            "requestedSchema": {"properties": {"note": {"type": "string"}}},
        },
    }
    response = handler.handle_request(payload)
    assert response["result"]["task"]["taskId"].startswith("task-1234abcd")
    assert "elic-1" in handler.elicitation.pending_ids


def test_form_content_from_schema_handles_arrays_and_defaults():
    schema = {
        "properties": {
            "flag": {"type": "boolean"},
            "items": {"type": "array", "items": {"type": "string", "default": "x"}},
        }
    }
    content = sr._form_content_from_schema(schema)
    assert content["flag"] is False
    assert content["items"] == ["x"]


def test_default_roots_and_jsonrpc_helpers(monkeypatch):
    monkeypatch.setattr(sr.Path, "cwd", lambda: sr.Path("/tmp/ws"))
    roots = sr._default_roots()
    assert roots[0]["uri"].endswith("/tmp/ws")
    result = sr._jsonrpc_result(1, {"ok": True})
    error = sr._jsonrpc_error(2, 400, "bad", data={"x": 1})
    assert result["id"] == 1 and result["result"]["ok"] is True
    assert error["error"]["data"] == {"x": 1} and error["id"] == 2


def test_first_enum_and_default_form_value_fallbacks():
    assert sr._first_enum_value({"anyOf": [{"const": "c"}]}) == "c"
    assert sr._first_enum_value({"enum": ["z"]}) == "z"
    assert sr._first_enum_value({"anyOf": ["not-dict"]}) is None
    # array with non-dict items returns []
    assert sr._default_form_value("arr", {"type": "array", "items": "x"}) == []
    assert sr._default_form_value("num", {"type": "number", "minimum": 2.5}) == 2.5
    assert sr._default_form_value("num", {"type": "number"}) == 0
    # object types ignored in _default_form_value
    assert sr._default_form_value("x", {"type": "string"}) == "x-value"
    assert sr._default_form_value(
        "nested", {"type": "array", "items": {"default": ["y"]}}
    ) == ["y"]


def test_form_content_invalid_input_is_empty():
    assert sr._form_content_from_schema(None) == {}
    assert sr._form_content_from_schema({"properties": "nope"}) == {}
    assert sr._form_content_from_schema({"properties": {"k": "not-dict"}}) == {}


def test_task_manager_error_and_unknown_paths():
    mgr = sr.TaskManager()
    empty_list = mgr.list_response(request_id=1)
    assert empty_list["result"]["tasks"] == []
    none_task = mgr.get_response(request_id=2, task_id=None)
    assert none_task["error"]["code"] == sr.JSONRPC_INVALID_PARAMS
    none_result = mgr.result_response(request_id=3, task_id=None)
    assert none_result["error"]["code"] == sr.JSONRPC_INVALID_PARAMS
    unknown_cancel = mgr.cancel_response(request_id=9, task_id="missing")
    assert unknown_cancel["error"]["code"] == sr.JSONRPC_INVALID_PARAMS
    # result path when error stored
    task = mgr._create_task(
        origin_method="tools/call",
        ttl=None,
        result=None,
        error={"code": 500, "message": "fail"},
    )
    err = mgr.result_response(request_id=3, task_id=task["taskId"])
    assert err["error"]["code"] == 500
    # task_aware_result with no task metadata returns final result
    response = mgr.task_aware_result(5, {}, origin_method="x", final_result={"a": 1})
    assert response["result"] == {"a": 1}
    # result path with existing result
    mgr.tasks[task["taskId"]].error = None
    mgr.tasks[task["taskId"]].result = {"ok": True}
    res = mgr.result_response(request_id=6, task_id=task["taskId"])
    assert res["result"]["ok"] is True


def test_handler_notifications_and_unknowns():
    handler = sr.ServerRequestHandler()
    # unknown notification -> False
    assert handler.handle_notification({"jsonrpc": "2.0", "method": "noop"}) is False
    # unknown request -> None
    assert (
        handler.handle_request({"jsonrpc": "2.0", "id": 1, "method": "noop"}) is None
    )
    # tracked notification without handler -> True and logged
    notified = handler.handle_notification(
        {"jsonrpc": "2.0", "method": sr.NOTIFY_MESSAGE, "params": {"text": "hi"}}
    )
    assert notified is True
    assert handler.notifications.logs[-1]["text"] == "hi"


def test_handler_custom_overrides_are_used():
    called = {}

    def custom_req(req_id, params):
        called["req"] = (req_id, params)
        return {"custom": True}

    def custom_notif(params):
        called["notif"] = params
        return False

    handler = sr.ServerRequestHandler(
        request_handlers={"x/custom": custom_req},
        notification_handlers={sr.NOTIFY_MESSAGE: custom_notif},
    )
    req_resp = handler.handle_request(
        {"jsonrpc": "2.0", "id": 5, "method": "x/custom", "params": {"k": 1}}
    )
    assert req_resp == {"custom": True}
    assert called["req"][0] == 5

    notif_resp = handler.handle_notification(
        {"jsonrpc": "2.0", "method": sr.NOTIFY_MESSAGE, "params": {"p": 50}}
    )
    assert notif_resp is False
    assert called["notif"] == {"p": 50}


def test_build_sampling_and_roots_and_elicitation_helpers():
    resp = sr.build_sampling_create_message_response(10, params=None)
    assert resp["id"] == 10 and resp["result"]["role"] == "assistant"
    roots = sr.build_roots_list_response(11)
    assert roots["result"]["roots"]
    elic_resp = sr.build_elicitation_create_response(12, params={"mode": "url"})
    assert elic_resp["id"] == 12 and elic_resp["result"]["action"] == "accept"
    elicit = sr.build_elicitation_create_result({"mode": "url"})
    assert "content" not in elicit


def test_notification_log_records_message():
    log = sr.NotificationLog()
    log.record(sr.NOTIFY_MESSAGE, {"text": "hi"})
    assert sr.NOTIFY_MESSAGE in log.methods
    assert log.logs[-1]["text"] == "hi"


def test_extract_task_id_invalid_values():
    assert sr.TaskManager.extract_task_id({"taskId": ""}) is None
    assert sr.TaskManager.extract_task_id({"taskId": 123}) is None
    assert sr.TaskManager.extract_task_id({"taskId": "ok"}) == "ok"
