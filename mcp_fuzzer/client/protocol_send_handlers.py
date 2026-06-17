"""Transport send handlers for MCP protocol messages."""

from typing import Any

from ..protocol_registry import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST
from .protocol_specs import _PROTOCOL_SPECS


class ProtocolSendHandlers:
    """Mixin providing protocol message send dispatch and handlers."""

    async def _send_protocol_request(
        self, protocol_type: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Send a protocol request based on the type."""
        spec = _PROTOCOL_SPECS.get(protocol_type)
        handler_name = (
            spec.handler_name if spec is not None else "_send_generic_request"
        )
        handler = getattr(self, handler_name)
        return await handler(data)

    async def _send_notification(self, method: str, data: Any) -> dict[str, str]:
        params = self._extract_params(data)
        await self.transport.send_notification(method, params)
        return {"status": "notification_sent"}

    async def _send_initialize_request(self, data: Any) -> dict[str, Any]:
        """Send an initialize request."""
        return await self._send_protocol_action("InitializeRequest", data)

    async def _send_initialized_notification(self, data: Any) -> dict[str, str]:
        """Send the initialized notification."""
        return await self._send_protocol_action("InitializedNotification", data)

    async def _send_progress_notification(self, data: Any) -> dict[str, str]:
        """Send a progress notification as JSON-RPC notification (no id)."""
        return await self._send_protocol_action("ProgressNotification", data)

    async def _send_cancelled_notification(self, data: Any) -> dict[str, str]:
        """Send a cancelled notification as JSON-RPC notification (no id)."""
        return await self._send_protocol_action("CancelledNotification", data)

    async def _send_list_tools_request(self, data: Any) -> dict[str, Any]:
        """Send a list tools request."""
        return await self._send_protocol_action("ListToolsRequest", data)

    async def _send_call_tool_request(self, data: Any) -> dict[str, Any]:
        """Send a tool call request."""
        return await self._send_protocol_action("CallToolRequest", data)

    async def _send_list_resources_request(self, data: Any) -> dict[str, Any]:
        """Send a list resources request."""
        return await self._send_protocol_action("ListResourcesRequest", data)

    async def _send_read_resource_request(self, data: Any) -> dict[str, Any]:
        """Send a read resource request."""
        return await self._send_protocol_action(READ_RESOURCE_REQUEST, data)

    async def _send_list_resource_templates_request(self, data: Any) -> dict[str, Any]:
        """Send a list resource templates request."""
        return await self._send_protocol_action("ListResourceTemplatesRequest", data)

    async def _send_set_level_request(self, data: Any) -> dict[str, Any]:
        """Send a set level request."""
        return await self._send_protocol_action("SetLevelRequest", data)

    async def _send_create_message_request(self, data: Any) -> dict[str, Any]:
        """Send a create message request."""
        return await self._send_protocol_action("CreateMessageRequest", data)

    async def _send_list_prompts_request(self, data: Any) -> dict[str, Any]:
        """Send a list prompts request."""
        return await self._send_protocol_action("ListPromptsRequest", data)

    async def _send_get_prompt_request(self, data: Any) -> dict[str, Any]:
        """Send a get prompt request."""
        return await self._send_protocol_action(GET_PROMPT_REQUEST, data)

    async def _send_list_roots_request(self, data: Any) -> dict[str, Any]:
        """Send a list roots request."""
        return await self._send_protocol_action("ListRootsRequest", data)

    async def _send_subscribe_request(self, data: Any) -> dict[str, Any]:
        """Send a subscribe request."""
        return await self._send_protocol_action("SubscribeRequest", data)

    async def _send_unsubscribe_request(self, data: Any) -> dict[str, Any]:
        """Send an unsubscribe request."""
        return await self._send_protocol_action("UnsubscribeRequest", data)

    async def _send_complete_request(self, data: Any) -> dict[str, Any]:
        """Send a complete request."""
        return await self._send_protocol_action("CompleteRequest", data)

    async def _send_elicit_request(self, data: Any) -> dict[str, Any]:
        """Send an elicitation request."""
        return await self._send_protocol_action("ElicitRequest", data)

    async def _send_list_tasks_request(self, data: Any) -> dict[str, Any]:
        """Send a list tasks request."""
        return await self._send_protocol_action("ListTasksRequest", data)

    async def _send_get_task_request(self, data: Any) -> dict[str, Any]:
        """Send a get task request."""
        return await self._send_protocol_action("GetTaskRequest", data)

    async def _send_get_task_payload_request(self, data: Any) -> dict[str, Any]:
        """Send a get task payload request."""
        return await self._send_protocol_action("GetTaskPayloadRequest", data)

    async def _send_cancel_task_request(self, data: Any) -> dict[str, Any]:
        """Send a cancel task request."""
        return await self._send_protocol_action("CancelTaskRequest", data)

    async def _send_ping_request(self, data: Any) -> dict[str, Any]:
        """Send a ping request."""
        return await self._send_protocol_action("PingRequest", data)

    async def _send_protocol_action(
        self, protocol_type: str, data: Any
    ) -> dict[str, Any] | dict[str, str]:
        spec = _PROTOCOL_SPECS[protocol_type]
        method = spec.method
        if spec.is_notification:
            return await self._send_notification(method, data)
        return await self._send_request(method, data)

    async def _send_request(self, method: str, data: Any) -> dict[str, Any]:
        return await self.transport.send_request(method, self._extract_params(data))

    async def _send_generic_request(self, data: Any) -> dict[str, Any]:
        """Send a generic JSON-RPC request."""
        method = data.get("method") if isinstance(data, dict) else None
        if not isinstance(method, str) or not method:
            method = "unknown"
        params = self._extract_params(data)
        return await self.transport.send_request(method, params)

    def _extract_params(self, data: Any) -> dict[str, Any]:
        """Extract parameters from data, safely handling non-dict inputs.

        Args:
            data: Input data that may or may not be a dict

        Returns:
            Dictionary of parameters, or empty dict if not available
        """
        if isinstance(data, dict):
            params = data.get("params", {})
            if isinstance(params, dict):
                return params
        self._logger.debug(
            "Coercing non-dict params to empty dict for %s", type(data).__name__
        )
        return {}
