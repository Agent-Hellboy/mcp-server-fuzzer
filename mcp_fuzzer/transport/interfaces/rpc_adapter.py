"""JSON-RPC helper utilities for transport layer.

This module provides shared JSON-RPC functionality that was previously
embedded in the TransportDriver base class. The JsonRpcAdapter can be
composed into transports or used standalone.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .driver import TransportDriver



class JsonRpcAdapter:
    """Helper class providing JSON-RPC operations for transports.

    This class can be composed into transport implementations or used
    standalone to perform common JSON-RPC operations like fetching tools,
    calling tools, and handling batch requests.
    """

    def __init__(self, transport: TransportDriver | None = None):
        """Initialize the JSON-RPC helper.

        Args:
            transport: Optional transport to use for requests. Can be set later.
        """
        self._transport = transport
        self._logger = logging.getLogger(__name__)

    def set_transport(self, transport: TransportDriver) -> None:
        """Set or update the transport used for requests.

        Args:
            transport: Transport instance to use
        """
        self._transport = transport

    def _require_transport(self) -> TransportDriver:
        if not self._transport:
            raise RuntimeError("No transport set for JsonRpcAdapter")
        return self._transport

    async def get_tools(self) -> list[dict[str, Any]]:
        """Fetch the list of available tools from the server.

        Returns:
            List of tool definitions from the server

        Raises:
            RuntimeError: If no transport is set
        """
        transport = self._require_transport()

        try:
            response = await transport.send_request("tools/list")
            self._logger.debug("Raw server response: %s", response)

            if not isinstance(response, dict):
                self._logger.warning(
                    "Server response is not a dictionary. Got type: %s",
                    type(response),
                )
                return []

            if "tools" in response:
                tools = response["tools"]
            else:
                result = response.get("result")
                if isinstance(result, dict) and "tools" in result:
                    tools = result["tools"]
                elif "error" in response:
                    self._logger.warning(
                        "Server returned error for tools/list: %s",
                        response.get("error"),
                    )
                    return []
                else:
                    self._logger.warning(
                        "Server response missing 'tools' key. Keys present: %s",
                        list(response.keys()),
                    )
                    return []
            self._logger.info("Found %d tools from server", len(tools))
            return tools
        except Exception as e:
            self._logger.exception("Failed to fetch tools from server: %s", e)
            return []

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Call a tool on the server with the given arguments.

        Note: Safety checks and sanitization are handled at the client layer,
        NOT in the transport. This keeps the transport layer focused on
        communication concerns only.

        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool

        Returns:
            Tool execution result from the server

        Raises:
            RuntimeError: If no transport is set
        """
        transport = self._require_transport()

        if params is None:
            params = {"name": tool_name, "arguments": arguments}
        return await transport.send_request("tools/call", params)

    async def ping(self) -> Any:
        """Send a ping request to the server."""
        transport = self._require_transport()
        return await transport.send_request("ping")

    async def set_logging_level(self, level: str) -> Any:
        """Set the server logging level."""
        transport = self._require_transport()
        return await transport.send_request("logging/setLevel", {"level": level})

    async def list_resources(self) -> Any:
        """Fetch available resources."""
        transport = self._require_transport()
        return await transport.send_request("resources/list")

    async def list_resource_templates(self) -> Any:
        """Fetch available resource templates."""
        transport = self._require_transport()
        return await transport.send_request("resources/templates/list")

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        transport = self._require_transport()
        return await transport.send_request("resources/read", {"uri": uri})

    async def subscribe_resource(self, uri: str) -> Any:
        """Subscribe to resource updates."""
        transport = self._require_transport()
        return await transport.send_request("resources/subscribe", {"uri": uri})

    async def unsubscribe_resource(self, uri: str) -> Any:
        """Unsubscribe from resource updates."""
        transport = self._require_transport()
        return await transport.send_request("resources/unsubscribe", {"uri": uri})

    async def list_prompts(self) -> Any:
        """Fetch available prompts."""
        transport = self._require_transport()
        return await transport.send_request("prompts/list")

    async def get_prompt(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        """Get a prompt by name with optional arguments."""
        transport = self._require_transport()
        params = {"name": name, "arguments": arguments or {}}
        return await transport.send_request("prompts/get", params)

    async def complete(
        self, prompt: str, arguments: dict[str, Any] | None = None
    ) -> Any:
        """Run completion for a prompt."""
        transport = self._require_transport()
        arguments = arguments or {}
        argument_items = [
            {"name": name, "value": value} for name, value in arguments.items()
        ]
        if not argument_items:
            argument_payload: Any = {"name": "query", "value": ""}
        elif len(argument_items) == 1:
            argument_payload = argument_items[0]
        else:
            argument_payload = argument_items
        params = {
            "ref": {"type": "ref/prompt", "name": prompt},
            "argument": argument_payload,
        }
        return await transport.send_request("completion/complete", params)

    async def send_batch_request(
        self, batch: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Send a batch of JSON-RPC requests/notifications.

        Args:
            batch: List of JSON-RPC requests/notifications

        Returns:
            List of responses (may be out of order or incomplete)

        Raises:
            RuntimeError: If no transport is set
        """
        transport = self._require_transport()

        # Default implementation sends each request individually
        # Transports can override for true batch support
        responses = []
        for request in batch:
            try:
                if "id" not in request or request["id"] is None:
                    # Notification - no response expected
                    await transport.send_raw(request)
                else:
                    # Request - response expected
                    response = await transport.send_raw(request)
                    # Normalize to dict
                    if not isinstance(response, dict):
                        response = {"result": response}
                    # Ensure ID is present for collation
                    req_id = request.get("id")
                    if req_id is not None and "id" not in response:
                        response["id"] = req_id
                    responses.append(response)
            except Exception as e:
                self._logger.warning(f"Failed to send batch request: {e}")
                responses.append({"error": str(e), "id": request.get("id")})

        return responses

    def collate_batch_responses(
        self, requests: list[dict[str, Any]], responses: list[dict[str, Any]]
    ) -> dict[Any, dict[str, Any]]:
        """Collate batch responses by ID, handling out-of-order and missing responses.

        Args:
            requests: Original batch requests
            responses: Server responses

        Returns:
            Dictionary mapping request IDs to responses
        """
        # Create mapping of expected IDs to requests
        expected_responses = {}
        for request in requests:
            if "id" in request and request["id"] is not None:
                expected_responses[request["id"]] = request

        # Map responses to requests by ID
        collated = {}
        for response in responses:
            response_id = response.get("id")
            if response_id in expected_responses:
                collated[response_id] = response
            else:
                # Unmatched response - could be error or notification response
                self._logger.warning(
                    f"Received response with unmatched ID: {response_id}"
                )

        # Check for missing responses
        for req_id, request in expected_responses.items():
            if req_id not in collated:
                collated[req_id] = {
                    "error": {"code": -32000, "message": "Response missing"},
                    "id": req_id,
                }

        return collated
