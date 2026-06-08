"""String constants for spec-guard check IDs."""


class CheckID:
    # tool schema / list
    TOOL_NAME = "tool-name"
    TOOL_SCHEMA_SCHEMA = "tool-schema-$schema"
    TOOL_SCHEMA_DEFS = "tool-schema-$defs"
    TOOL_SCHEMA_ADDITIONAL_PROPERTIES = "tool-schema-additional-properties"
    TOOL_ICONS_TYPE = "tool-icons-type"
    TOOL_ICON_ITEM = "tool-icon-item"
    TOOL_ICON_SRC = "tool-icon-src"
    TOOL_EXECUTION_TYPE = "tool-execution-type"
    TOOL_EXECUTION_TASK_SUPPORT = "tool-execution-task-support"
    TOOLS_LIST_MISSING = "tools-list-missing"
    TOOLS_LIST_TYPE = "tools-list-type"
    TOOLS_LIST_ITEM = "tools-list-item"

    # tasks
    TASKS_LIST_MISSING = "tasks-list-missing"
    TASKS_LIST_TYPE = "tasks-list-type"
    TASKS_RESULT_TYPE = "tasks-result-type"

    # roots
    ROOTS_LIST_MISSING = "roots-list-missing"
    ROOTS_LIST_TYPE = "roots-list-type"
    ROOTS_LIST_ITEM = "roots-list-item"
    ROOTS_LIST_URI = "roots-list-uri"

    # sampling / createMessage
    SAMPLING_MODEL = "sampling-model"
    SAMPLING_ROLE = "sampling-role"
    SAMPLING_CONTENT = "sampling-content"
    SAMPLING_STOP_REASON = "sampling-stop-reason"

    # elicitation
    ELICITATION_ACTION = "elicitation-action"
    ELICITATION_CONTENT = "elicitation-content"
    ELICITATION_COMPLETE_PARAMS = "elicitation-complete-params"
    ELICITATION_COMPLETE_ID = "elicitation-complete-id"

    # tool result content
    TOOLS_CONTENT_ARRAY = "tools-content-array"
    TOOLS_CONTENT_EMPTY = "tools-content-empty"
    TOOLS_CONTENT_ITEM = "tools-content-item"
    TOOLS_CONTENT_TYPE = "tools-content-type"
    TOOLS_CONTENT_TEXT = "tools-content-text"
    TOOLS_CONTENT_IMAGE_DATA = "tools-content-image-data"
    TOOLS_CONTENT_IMAGE_MIME = "tools-content-image-mime"
    TOOLS_CONTENT_AUDIO_UNSUPPORTED = "tools-content-audio-unsupported"
    TOOLS_CONTENT_AUDIO_DATA = "tools-content-audio-data"
    TOOLS_CONTENT_AUDIO_MIME = "tools-content-audio-mime"
    TOOLS_CONTENT_RESOURCE = "tools-content-resource"
    TOOLS_CONTENT_RESOURCE_URI = "tools-content-resource-uri"
    TOOLS_CONTENT_RESOURCE_BODY = "tools-content-resource-body"
    TOOLS_CONTENT_RESOURCE_LINK_UNSUPPORTED = "tools-content-resource-link-unsupported"
    TOOLS_CONTENT_RESOURCE_LINK_URI = "tools-content-resource-link-uri"
    TOOLS_CONTENT_RESOURCE_LINK_NAME = "tools-content-resource-link-name"
    TOOLS_CONTENT_UNKNOWN_TYPE = "tools-content-unknown-type"
    TOOLS_ERROR_TEXT = "tools-error-text"

    # logging
    LOGGING_PARAMS_MISSING = "logging-params-missing"
    LOGGING_PARAMS_TYPE = "logging-params-type"
    LOGGING_LEVEL_MISSING = "logging-level-missing"
    LOGGING_LEVEL_TYPE = "logging-level-type"
    LOGGING_DATA_MISSING = "logging-data-missing"
    LOGGING_LOGGER_TYPE = "logging-logger-type"

    # progress notification
    PROGRESS_PARAMS_TYPE = "progress-params-type"
    PROGRESS_TOKEN_MISSING = "progress-token-missing"
    PROGRESS_TOKEN_TYPE = "progress-token-type"
    PROGRESS_VALUE_MISSING = "progress-value-missing"
    PROGRESS_VALUE_TYPE = "progress-value-type"
    PROGRESS_TOTAL_TYPE = "progress-total-type"

    # cancelled notification
    CANCELLED_PARAMS_TYPE = "cancelled-params-type"
    CANCELLED_REQUEST_ID_MISSING = "cancelled-request-id-missing"
    CANCELLED_REQUEST_ID_TYPE = "cancelled-request-id-type"
    CANCELLED_REASON_TYPE = "cancelled-reason-type"

    # list_changed notification
    LIST_CHANGED_PARAMS_TYPE = "list-changed-params-type"

    # resources/updated notification
    RESOURCES_UPDATED_PARAMS_TYPE = "resources-updated-params-type"
    RESOURCES_UPDATED_URI_MISSING = "resources-updated-uri-missing"

    # resources/list
    RESOURCES_LIST_MISSING = "resources-list-missing"
    RESOURCES_LIST_TYPE = "resources-list-type"
    RESOURCES_LIST_ITEM = "resources-list-item"
    RESOURCES_LIST_URI = "resources-list-uri"
    RESOURCES_LIST_NAME = "resources-list-name"

    # resources/read
    RESOURCES_READ_MISSING = "resources-read-missing"
    RESOURCES_READ_TYPE = "resources-read-type"
    RESOURCES_READ_EMPTY = "resources-read-empty"
    RESOURCES_READ_URI = "resources-read-uri"
    RESOURCES_READ_BODY = "resources-read-body"
    RESOURCES_READ_ITEM = "resources-read-item"

    # resources/templates/list
    RESOURCES_TEMPLATES_MISSING = "resources-templates-missing"
    RESOURCES_TEMPLATES_TYPE = "resources-templates-type"
    RESOURCES_TEMPLATES_ITEM = "resources-templates-item"
    RESOURCES_TEMPLATES_URI = "resources-templates-uri"
    RESOURCES_TEMPLATES_NAME = "resources-templates-name"

    # prompts/list
    PROMPTS_LIST_MISSING = "prompts-list-missing"
    PROMPTS_LIST_TYPE = "prompts-list-type"
    PROMPTS_LIST_ITEM = "prompts-list-item"
    PROMPTS_LIST_NAME = "prompts-list-name"

    # prompts/get
    PROMPTS_GET_MISSING = "prompts-get-missing"
    PROMPTS_GET_TYPE = "prompts-get-type"
    PROMPTS_GET_EMPTY = "prompts-get-empty"
    PROMPTS_GET_ITEM = "prompts-get-item"
    PROMPTS_GET_ROLE = "prompts-get-role"
    PROMPTS_GET_CONTENT = "prompts-get-content"

    # completion/complete
    COMPLETION_MISSING = "completion-missing"
    COMPLETION_TYPE = "completion-type"
    COMPLETION_VALUES_MISSING = "completion-values-missing"
    COMPLETION_VALUES_TYPE = "completion-values-type"
    COMPLETION_VALUES_ITEM = "completion-values-item"
    COMPLETION_HAS_MORE_TYPE = "completion-has-more-type"
    COMPLETION_TOTAL_TYPE = "completion-total-type"

    # subscribe / unsubscribe
    SUBSCRIBE_RESULT_TYPE = "subscribe-result-type"
    UNSUBSCRIBE_RESULT_TYPE = "unsubscribe-result-type"

    # SSE
    SSE_RETRY_NONINT = "sse-retry-nonint"
    SSE_ID_EMPTY = "sse-id-empty"
    SSE_NO_DATA = "sse-no-data"
