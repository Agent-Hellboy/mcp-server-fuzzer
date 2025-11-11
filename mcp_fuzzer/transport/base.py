from abc import ABC, abstractmethod
import logging
from typing import Any, AsyncIterator


class TransportProtocol(ABC):
    @abstractmethod
    async def send_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> Any:
        pass

    @abstractmethod
    async def send_raw(self, payload: dict[str, Any]) -> Any:
        pass

    @abstractmethod
    async def send_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None:
        pass

    async def connect(self) -> None:
        """Connect to the transport. Default implementation does nothing."""
        pass

    async def disconnect(self) -> None:
        """Disconnect from the transport. Default implementation does nothing."""
        pass

    async def stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream a request to the transport.

        Args:
            payload: The request payload

        Yields:
            Response chunks from the transport
        """
        async for response in self._stream_request(payload):
            yield response

    @abstractmethod
    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        """Subclasses must implement streaming of requests."""
        pass

    async def get_tools(self) -> list[dict[str, Any]]:
        try:
            response = await self.send_request("tools/list")
            logging.debug("Raw server response: %s", response)
            if not isinstance(response, dict):
                logging.warning(
                    "Server response is not a dictionary. Got type: %s",
                    type(response),
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

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """
        Call a tool on the server with the given arguments.

        Note: Safety checks and sanitization are handled at the client layer,
        NOT in the transport. This keeps the transport layer focused on
        communication concerns only.
        """
        params = {"name": tool_name, "arguments": arguments}
        return await self.send_request("tools/call", params)

    async def send_batch_request(
        self, batch: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Send a batch of JSON-RPC requests/notifications.

        Args:
            batch: List of JSON-RPC requests/notifications

        Returns:
            List of responses (may be out of order or incomplete)
        """
        # Default implementation sends each request individually
        # Subclasses can override for true batch support
        responses = []
        for request in batch:
            try:
                if "id" not in request or request["id"] is None:
                    # Notification - no response expected
                    await self.send_raw(request)
                else:
                    # Request - response expected
                    response = await self.send_raw(request)
                    # Normalize to dict
                    if not isinstance(response, dict):
                        response = {"result": response}
                    # Ensure ID is present for collation
                    req_id = request.get("id")
                    if req_id is not None and "id" not in response:
                        response["id"] = req_id
                    responses.append(response)
            except Exception as e:
                logging.warning(f"Failed to send batch request: {e}")
                responses.append({"error": str(e), "id": request.get("id")})

        return responses

    def collate_batch_responses(
        self, requests: list[dict[str, Any]], responses: list[dict[str, Any]]
    ) -> dict[Any, dict[str, Any]]:
        """
        Collate batch responses by ID, handling out-of-order and missing responses.

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
                logging.warning(f"Received response with unmatched ID: {response_id}")

        # Check for missing responses
        for req_id, request in expected_responses.items():
            if req_id not in collated:
                collated[req_id] = {
                    "error": {"code": -32000, "message": "Response missing"},
                    "id": req_id,
                }

        return collated
