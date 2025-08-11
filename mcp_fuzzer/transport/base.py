from abc import ABC, abstractmethod
import logging
from typing import Any, Dict, Optional, List

from ..safety_system.safety import (
    safety_filter,
    is_safe_tool_call,
    create_safety_response,
    sanitize_tool_call,
)


class TransportProtocol(ABC):
    @abstractmethod
    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        pass

    @abstractmethod
    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        pass

    async def get_tools(self) -> List[Dict[str, Any]]:
        try:
            response = await self.send_request("tools/list")
            logging.debug("Raw server response: %s", response)
            if not isinstance(response, dict):
                logging.warning(
                    "Server response is not a dictionary. Got type: %s", type(response)
                )
                return []
            if "tools" not in response:
                logging.warning(
                    "Server response missing 'tools' key. Keys present: %s",
                    list(response.keys()),
                )
                return []
            tools = response["tools"]
            logging.info("Found %d tools from server", len(tools))
            return tools
        except Exception as e:
            logging.exception("Failed to fetch tools from server: %s", e)
            return []

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        if not is_safe_tool_call(tool_name, arguments):
            safety_filter.log_blocked_operation(
                tool_name, arguments, "Dangerous tool call blocked in transport"
            )
            return create_safety_response(tool_name)

        sanitized_tool_name, sanitized_arguments = sanitize_tool_call(
            tool_name, arguments
        )
        safety_sanitized = sanitized_arguments != arguments
        params = {"name": sanitized_tool_name, "arguments": sanitized_arguments}
        result = await self.send_request("tools/call", params)
        if safety_sanitized and isinstance(result, dict):
            if "_meta" not in result:
                result["_meta"] = {}
            result["_meta"]["safety_sanitized"] = True
            result["_meta"]["original_arguments"] = arguments
            result["_meta"]["sanitized_arguments"] = sanitized_arguments
        return result
