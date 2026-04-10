"""Shared JSON-RPC method and notification names to avoid magic strings."""

# Requests
ROOTS_LIST = "roots/list"
SAMPLING_CREATE_MESSAGE = "sampling/createMessage"
ELICITATION_CREATE = "elicitation/create"
TASKS_LIST = "tasks/list"
TASKS_GET = "tasks/get"
TASKS_RESULT = "tasks/result"
TASKS_CANCEL = "tasks/cancel"

# Notifications
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
