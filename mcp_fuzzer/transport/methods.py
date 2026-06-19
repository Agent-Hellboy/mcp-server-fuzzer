"""Shared JSON-RPC method names and helpers used by transports."""

from __future__ import annotations

from typing import Any

# Requests
INITIALIZE = "initialize"
TOOLS_LIST = "tools/list"
PROMPTS_LIST = "prompts/list"
RESOURCES_LIST = "resources/list"
ROOTS_LIST = "roots/list"
SAMPLING_CREATE_MESSAGE = "sampling/createMessage"
ELICITATION_CREATE = "elicitation/create"
TASKS_LIST = "tasks/list"
TASKS_GET = "tasks/get"
TASKS_RESULT = "tasks/result"
TASKS_CANCEL = "tasks/cancel"

# Notifications
NOTIFY_INITIALIZED = "notifications/initialized"
NOTIFY_ELICITATION_COMPLETE = "notifications/elicitation/complete"
NOTIFY_MESSAGE = "notifications/message"
NOTIFY_PROGRESS = "notifications/progress"
NOTIFY_TASKS_STATUS = "notifications/tasks/status"
NOTIFY_PROMPTS_LIST_CHANGED = "notifications/prompts/list_changed"
NOTIFY_RESOURCES_LIST_CHANGED = "notifications/resources/list_changed"
NOTIFY_RESOURCES_UPDATED = "notifications/resources/updated"
NOTIFY_ROOTS_LIST_CHANGED = "notifications/roots/list_changed"
NOTIFY_TOOLS_LIST_CHANGED = "notifications/tools/list_changed"

LIST_CHANGED_NOTIFICATIONS = frozenset(
    {
        NOTIFY_PROMPTS_LIST_CHANGED,
        NOTIFY_RESOURCES_LIST_CHANGED,
        NOTIFY_RESOURCES_UPDATED,
        NOTIFY_ROOTS_LIST_CHANGED,
        NOTIFY_TOOLS_LIST_CHANGED,
    }
)

TRACKED_NOTIFICATIONS = LIST_CHANGED_NOTIFICATIONS | {
    NOTIFY_ELICITATION_COMPLETE,
    NOTIFY_MESSAGE,
    NOTIFY_PROGRESS,
    NOTIFY_TASKS_STATUS,
}

MCP_SESSION_BOOTSTRAP_METHODS = frozenset({INITIALIZE, NOTIFY_INITIALIZED})

RETRY_SAFE_REQUEST_METHODS = frozenset(
    {
        INITIALIZE,
        NOTIFY_INITIALIZED,
        TOOLS_LIST,
        PROMPTS_LIST,
        RESOURCES_LIST,
    }
)


def payload_method(payload: Any) -> str | None:
    """Return the JSON-RPC method for request-like payloads."""
    if not isinstance(payload, dict):
        return None
    method = payload.get("method")
    return method if isinstance(method, str) else None


def is_initialize_method(method: str | None) -> bool:
    return method == INITIALIZE


def is_initialized_notification(method: str | None) -> bool:
    return method == NOTIFY_INITIALIZED


def requires_mcp_initialization(method: str | None) -> bool:
    return method not in MCP_SESSION_BOOTSTRAP_METHODS


def is_retry_safe_method(method: str | None) -> bool:
    return method in RETRY_SAFE_REQUEST_METHODS
