"""Helpers for server-initiated requests handled by the client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import uuid

JSONRPC_CANCELLED = -32800
JSONRPC_INVALID_PARAMS = -32602

_LIST_CHANGED_NOTIFICATIONS = frozenset(
    {
        "notifications/prompts/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/roots/list_changed",
        "notifications/tools/list_changed",
    }
)

_TRACKED_NOTIFICATIONS = frozenset(
    {
        "notifications/elicitation/complete",
        "notifications/message",
        "notifications/progress",
        "notifications/tasks/status",
    }
) | _LIST_CHANGED_NOTIFICATIONS


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
            return [nested_default] if not isinstance(nested_default, list) else nested_default
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


class ServerRequestState:
    """Track client-side state for server-initiated requests and notifications."""

    def __init__(self, roots: list[dict[str, Any]] | None = None):
        self.roots = list(roots) if roots else _default_roots()
        self.tasks: dict[str, TaskRecord] = {}
        self.pending_elicitation_ids: set[str] = set()
        self.completed_elicitation_ids: set[str] = set()
        self.logs: list[dict[str, Any]] = []
        self.notification_methods: list[str] = []

    def handle_request(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Build a client response for a server-initiated request."""
        if not is_server_request(payload):
            return None

        method = payload.get("method")
        request_id = payload.get("id")
        params = payload.get("params")
        params = params if isinstance(params, dict) else {}

        if method == "roots/list":
            return build_roots_list_response(request_id, roots=self.roots)

        if method == "sampling/createMessage":
            final_result = build_sampling_create_message_result(params)
            return self._task_aware_result(
                request_id,
                params,
                origin_method=method,
                final_result=final_result,
            )

        if method == "elicitation/create":
            elicitation_id = params.get("elicitationId")
            if isinstance(elicitation_id, str) and elicitation_id:
                self.pending_elicitation_ids.add(elicitation_id)
            final_result = build_elicitation_create_result(params)
            return self._task_aware_result(
                request_id,
                params,
                origin_method=method,
                final_result=final_result,
            )

        if method == "tasks/list":
            return _jsonrpc_result(
                request_id,
                {"tasks": [record.task.copy() for record in self.tasks.values()]},
            )

        if method == "tasks/get":
            task_id = self._extract_task_id(params)
            if task_id is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "tasks/get requires a valid taskId",
                )
            record = self.tasks.get(task_id)
            if record is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "Unknown taskId",
                )
            return _jsonrpc_result(request_id, record.task.copy())

        if method == "tasks/result":
            task_id = self._extract_task_id(params)
            if task_id is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "tasks/result requires a valid taskId",
                )
            record = self.tasks.get(task_id)
            if record is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "Unknown taskId",
                )
            if record.error is not None:
                return _jsonrpc_error(
                    request_id,
                    int(record.error.get("code", JSONRPC_CANCELLED)),
                    str(record.error.get("message", "Task failed")),
                    data=record.error.get("data"),
                )
            return _jsonrpc_result(request_id, dict(record.result or {}))

        if method == "tasks/cancel":
            task_id = self._extract_task_id(params)
            if task_id is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "tasks/cancel requires a valid taskId",
                )
            record = self.tasks.get(task_id)
            if record is None:
                return _jsonrpc_error(
                    request_id,
                    JSONRPC_INVALID_PARAMS,
                    "Unknown taskId",
                )
            now = _utc_now()
            record.task["status"] = "cancelled"
            record.task["statusMessage"] = "Cancelled by mcp-fuzzer"
            record.task["lastUpdatedAt"] = now
            record.error = {
                "code": JSONRPC_CANCELLED,
                "message": "Task cancelled",
            }
            return _jsonrpc_result(request_id, record.task.copy())

        return None

    def handle_notification(self, payload: dict[str, Any]) -> bool:
        """Update local state for server notifications."""
        if not is_server_notification(payload):
            return False

        method = payload.get("method")
        if not isinstance(method, str):
            return False

        params = payload.get("params")
        params = params if isinstance(params, dict) else {}

        if method not in _TRACKED_NOTIFICATIONS:
            return False

        self.notification_methods.append(method)

        if method == "notifications/message":
            self.logs.append(dict(params))
            return True

        if method == "notifications/elicitation/complete":
            elicitation_id = params.get("elicitationId")
            if (
                isinstance(elicitation_id, str)
                and elicitation_id in self.pending_elicitation_ids
                and elicitation_id not in self.completed_elicitation_ids
            ):
                self.pending_elicitation_ids.discard(elicitation_id)
                self.completed_elicitation_ids.add(elicitation_id)
            return True

        if method == "notifications/tasks/status":
            task_id = params.get("taskId")
            if isinstance(task_id, str) and task_id in self.tasks:
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
            return True

        return True

    @staticmethod
    def _extract_task_id(params: dict[str, Any]) -> str | None:
        task_id = params.get("taskId")
        if not isinstance(task_id, str) or not task_id:
            return None
        return task_id

    def _task_aware_result(
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


__all__ = [
    "JSONRPC_CANCELLED",
    "JSONRPC_INVALID_PARAMS",
    "ServerRequestState",
    "TaskRecord",
    "build_elicitation_create_response",
    "build_elicitation_create_result",
    "build_roots_list_response",
    "build_sampling_create_message_response",
    "build_sampling_create_message_result",
    "is_server_notification",
    "is_server_request",
]
