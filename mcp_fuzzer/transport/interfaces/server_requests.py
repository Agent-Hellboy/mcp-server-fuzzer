"""Helpers for server-initiated requests handled by the client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
import uuid

from ..methods import (
    ELICITATION_CREATE,
    NOTIFY_ELICITATION_COMPLETE,
    NOTIFY_MESSAGE,
    NOTIFY_TASKS_STATUS,
    ROOTS_LIST,
    SAMPLING_CREATE_MESSAGE,
    TASKS_CANCEL,
    TASKS_GET,
    TASKS_LIST,
    TASKS_RESULT,
    TRACKED_NOTIFICATIONS,
)

JSONRPC_CANCELLED = -32800
JSONRPC_INVALID_PARAMS = -32602


def is_server_request(payload: Any) -> bool:
    """Return True when payload looks like a JSON-RPC 2.0 server->client request."""
    return (
        isinstance(payload, dict)
        and payload.get("jsonrpc") == "2.0"
        and "method" in payload
        and "id" in payload
        and "result" not in payload
        and "error" not in payload
    )


def is_server_notification(payload: Any) -> bool:
    """Return True when payload looks like a JSON-RPC 2.0 notification."""
    return (
        isinstance(payload, dict)
        and payload.get("jsonrpc") == "2.0"
        and "method" in payload
        and "id" not in payload
        and "result" not in payload
        and "error" not in payload
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _default_roots() -> list[dict[str, str]]:
    workspace = Path.cwd().resolve()
    return [{"name": "workspace", "uri": workspace.as_uri()}]


def _jsonrpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    data: Any | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _first_enum_value(schema: dict[str, Any]) -> Any:
    enum_values = schema.get("enum")
    if isinstance(enum_values, list) and enum_values:
        return enum_values[0]

    for key in ("oneOf", "anyOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        for variant in variants:
            if isinstance(variant, dict) and "const" in variant:
                return variant["const"]
    return None


def _default_form_value(name: str, schema: dict[str, Any]) -> Any:
    if "default" in schema:
        return schema["default"]

    enum_value = _first_enum_value(schema)
    if enum_value is not None:
        return enum_value

    schema_type = schema.get("type")
    if schema_type == "boolean":
        return False
    if schema_type in {"integer", "number"}:
        minimum = schema.get("minimum")
        if isinstance(minimum, (int, float)):
            return minimum
        return 0
    if schema_type == "array":
        items = schema.get("items")
        if isinstance(items, dict):
            nested_default = _default_form_value(name, items)
            if not isinstance(nested_default, list):
                return [nested_default]
            return nested_default
        return []
    return f"{name}-value"


def _form_content_from_schema(requested_schema: Any) -> dict[str, Any]:
    if not isinstance(requested_schema, dict):
        return {}
    properties = requested_schema.get("properties")
    if not isinstance(properties, dict):
        return {}
    content: dict[str, Any] = {}
    for key, schema in properties.items():
        if not isinstance(key, str) or not isinstance(schema, dict):
            continue
        content[key] = _default_form_value(key, schema)
    return content


def build_sampling_create_message_result(
    params: dict[str, Any] | None = None,
    *,
    model: str = "mcp-fuzzer",
    text: str = "mcp-fuzzer sampling response",
) -> dict[str, Any]:
    """Build a minimal CreateMessageResult payload."""
    params = params if isinstance(params, dict) else {}
    tools = params.get("tools")
    tool_choice = params.get("toolChoice")
    tool_mode = tool_choice.get("mode") if isinstance(tool_choice, dict) else None

    if isinstance(tools, list) and tools and tool_mode != "none":
        tool_name = "tool"
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                tool_name = tool["name"]
                break
        content: Any = [
            {
                "type": "tool_use",
                "id": f"tool-use-{uuid.uuid4().hex[:8]}",
                "name": tool_name,
                "input": {},
            }
        ]
        stop_reason = "toolUse"
    else:
        content = {"type": "text", "text": text}
        stop_reason = "endTurn"

    return {
        "model": model,
        "role": "assistant",
        "content": content,
        "stopReason": stop_reason,
    }


def build_sampling_create_message_response(
    request_id: Any,
    *,
    model: str = "mcp-fuzzer",
    text: str = "mcp-fuzzer sampling response",
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a CreateMessageResult response for sampling/createMessage."""
    return _jsonrpc_result(
        request_id,
        build_sampling_create_message_result(params, model=model, text=text),
    )


def build_roots_list_response(
    request_id: Any,
    *,
    roots: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a ListRootsResult response."""
    return _jsonrpc_result(request_id, {"roots": roots or _default_roots()})


def build_elicitation_create_result(
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ElicitResult payload."""
    params = params if isinstance(params, dict) else {}
    mode = params.get("mode") if isinstance(params.get("mode"), str) else "form"
    result: dict[str, Any] = {"action": "accept"}
    if mode != "url":
        content = _form_content_from_schema(params.get("requestedSchema"))
        if content:
            result["content"] = content
    return result


def build_elicitation_create_response(
    request_id: Any,
    *,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an ElicitResult response for elicitation/create."""
    return _jsonrpc_result(request_id, build_elicitation_create_result(params))


@dataclass
class TaskRecord:
    """Minimal in-memory representation of a locally handled task."""

    task: dict[str, Any]
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    origin_method: str | None = None


class RootManager:
    def __init__(self, roots: list[dict[str, Any]] | None = None):
        self.roots = list(roots) if roots else _default_roots()

    def handle(self, request_id: Any) -> dict[str, Any]:
        return build_roots_list_response(request_id, roots=self.roots)


class TaskManager:
    def __init__(self) -> None:
        self.tasks: dict[str, TaskRecord] = {}

    def list_response(self, request_id: Any) -> dict[str, Any]:
        tasks = [record.task.copy() for record in self.tasks.values()]
        return _jsonrpc_result(request_id, {"tasks": tasks})

    def get_response(self, request_id: Any, task_id: str | None) -> dict[str, Any]:
        if task_id is None:
            return _jsonrpc_error(
                request_id, JSONRPC_INVALID_PARAMS, "tasks/get requires a valid taskId"
            )
        record = self.tasks.get(task_id)
        if record is None:
            return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "Unknown taskId")
        return _jsonrpc_result(request_id, record.task.copy())

    def result_response(self, request_id: Any, task_id: str | None) -> dict[str, Any]:
        if task_id is None:
            return _jsonrpc_error(
                request_id,
                JSONRPC_INVALID_PARAMS,
                "tasks/result requires a valid taskId",
            )
        record = self.tasks.get(task_id)
        if record is None:
            return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "Unknown taskId")
        if record.error is not None:
            return _jsonrpc_error(
                request_id,
                int(record.error.get("code", JSONRPC_CANCELLED)),
                str(record.error.get("message", "Task failed")),
                data=record.error.get("data"),
            )
        return _jsonrpc_result(request_id, dict(record.result or {}))

    def cancel_response(self, request_id: Any, task_id: str | None) -> dict[str, Any]:
        if task_id is None:
            return _jsonrpc_error(
                request_id,
                JSONRPC_INVALID_PARAMS,
                "tasks/cancel requires a valid taskId",
            )
        record = self.tasks.get(task_id)
        if record is None:
            return _jsonrpc_error(request_id, JSONRPC_INVALID_PARAMS, "Unknown taskId")
        now = _utc_now()
        record.task["status"] = "cancelled"
        record.task["statusMessage"] = "Cancelled by mcp-fuzzer"
        record.task["lastUpdatedAt"] = now
        record.error = {
            "code": JSONRPC_CANCELLED,
            "message": "Task cancelled",
        }
        return _jsonrpc_result(request_id, record.task.copy())

    def task_aware_result(
        self,
        request_id: Any,
        params: dict[str, Any],
        *,
        origin_method: str,
        final_result: dict[str, Any],
    ) -> dict[str, Any]:
        task_meta = params.get("task")
        if not isinstance(task_meta, dict):
            return _jsonrpc_result(request_id, final_result)

        task = self._create_task(
            origin_method=origin_method,
            ttl=task_meta.get("ttl"),
            result=final_result,
        )
        return _jsonrpc_result(request_id, {"task": task})

    def _create_task(
        self,
        *,
        origin_method: str,
        ttl: Any,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        task_id = f"task-{uuid.uuid4()}"
        now = _utc_now()
        ttl_value = ttl if isinstance(ttl, int) else 60000
        task = {
            "taskId": task_id,
            "status": "completed" if error is None else "failed",
            "statusMessage": (
                "Completed by mcp-fuzzer"
                if error is None
                else str(error.get("message", "Task failed"))
            ),
            "createdAt": now,
            "lastUpdatedAt": now,
            "ttl": ttl_value,
            "pollInterval": 250,
        }
        self.tasks[task_id] = TaskRecord(
            task=task.copy(),
            result=dict(result or {}),
            error=dict(error) if isinstance(error, dict) else None,
            origin_method=origin_method,
        )
        return task

    @staticmethod
    def extract_task_id(params: dict[str, Any]) -> str | None:
        task_id = params.get("taskId")
        if not isinstance(task_id, str) or not task_id:
            return None
        return task_id

    def update_status(self, params: dict[str, Any]) -> None:
        task_id = params.get("taskId")
        if not isinstance(task_id, str) or task_id not in self.tasks:
            return
        record = self.tasks[task_id]
        for key in (
            "createdAt",
            "lastUpdatedAt",
            "pollInterval",
            "status",
            "statusMessage",
            "taskId",
            "ttl",
        ):
            if key in params:
                record.task[key] = params[key]


class ElicitationTracker:
    def __init__(self) -> None:
        self.pending_ids: set[str] = set()
        self.completed_ids: set[str] = set()

    def record_request(self, params: dict[str, Any]) -> None:
        elicitation_id = params.get("elicitationId")
        if isinstance(elicitation_id, str) and elicitation_id:
            self.pending_ids.add(elicitation_id)

    def complete(self, params: dict[str, Any]) -> None:
        elicitation_id = params.get("elicitationId")
        if (
            isinstance(elicitation_id, str)
            and elicitation_id in self.pending_ids
            and elicitation_id not in self.completed_ids
        ):
            self.pending_ids.discard(elicitation_id)
            self.completed_ids.add(elicitation_id)


class NotificationLog:
    def __init__(self) -> None:
        self.logs: list[dict[str, Any]] = []
        self.methods: list[str] = []

    def record(self, method: str, params: dict[str, Any]) -> None:
        self.methods.append(method)
        if method == NOTIFY_MESSAGE:
            self.logs.append(dict(params))


class ServerRequestHandler:
    """Composable handler for server-initiated requests/notifications."""

    def __init__(
        self,
        roots: list[dict[str, Any]] | None = None,
        request_handlers: dict[str, callable] | None = None,
        notification_handlers: dict[str, callable] | None = None,
    ) -> None:
        self.roots = RootManager(roots)
        self.tasks = TaskManager()
        self.elicitation = ElicitationTracker()
        self.notifications = NotificationLog()
        # Default handlers; can be extended via constructor args for OCP.
        self._request_handlers: dict[str, callable] = {
            ROOTS_LIST: lambda rid, params: self.roots.handle(rid),
            SAMPLING_CREATE_MESSAGE: lambda rid, params: self.tasks.task_aware_result(
                rid,
                params,
                origin_method=SAMPLING_CREATE_MESSAGE,
                final_result=build_sampling_create_message_result(params),
            ),
            ELICITATION_CREATE: self._handle_elicitation_create,
            TASKS_LIST: lambda rid, params: self.tasks.list_response(rid),
            TASKS_GET: lambda rid, params: self.tasks.get_response(
                rid, TaskManager.extract_task_id(params)
            ),
            TASKS_RESULT: lambda rid, params: self.tasks.result_response(
                rid, TaskManager.extract_task_id(params)
            ),
            TASKS_CANCEL: lambda rid, params: self.tasks.cancel_response(
                rid, TaskManager.extract_task_id(params)
            ),
        }
        if request_handlers:
            self._request_handlers.update(request_handlers)

        self._notification_handlers: dict[str, callable] = {
            NOTIFY_ELICITATION_COMPLETE: lambda params: (
                self.elicitation.complete(params) or True
            ),
            NOTIFY_TASKS_STATUS: lambda params: (
                self.tasks.update_status(params) or True
            ),
        }
        if notification_handlers:
            self._notification_handlers.update(notification_handlers)

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        if not is_server_request(payload):
            return None

        method = payload.get("method")
        request_id = payload.get("id")
        raw_params = payload.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}

        handler = self._request_handlers.get(method)
        if handler:
            return handler(request_id, params)
        return None

    def handle_notification(self, payload: dict[str, Any]) -> bool:
        if not is_server_notification(payload):
            return False

        method = payload.get("method")
        if not isinstance(method, str) or method not in TRACKED_NOTIFICATIONS:
            return False

        raw_params = payload.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}

        self.notifications.record(method, params)
        handler = self._notification_handlers.get(method)
        if handler:
            return bool(handler(params))
        # Other notifications recorded only
        return True

    def _handle_elicitation_create(
        self, request_id: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        self.elicitation.record_request(params)
        final_result = build_elicitation_create_result(params)
        return self.tasks.task_aware_result(
            request_id,
            params,
            origin_method=ELICITATION_CREATE,
            final_result=final_result,
        )


@runtime_checkable
class ServerRequestHandlerProtocol(Protocol):
    """Minimal protocol for handling server-initiated messages."""

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        ...

    def handle_notification(self, payload: dict[str, Any]) -> bool:
        ...


__all__ = [
    "JSONRPC_CANCELLED",
    "JSONRPC_INVALID_PARAMS",
    "ServerRequestHandler",
    "ServerRequestHandlerProtocol",
    "TaskRecord",
    "build_elicitation_create_response",
    "build_elicitation_create_result",
    "build_roots_list_response",
    "build_sampling_create_message_response",
    "build_sampling_create_message_result",
    "is_server_notification",
    "is_server_request",
]
