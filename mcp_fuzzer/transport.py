"""
Transport layer for MCP fuzzer supporting multiple protocols.
"""

import asyncio
import json
import logging
import shlex
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
import websockets

from .safety import (
    safety_filter,
    is_safe_tool_call,
    create_safety_response,
    sanitize_tool_call,
)


class TransportProtocol(ABC):
    """Abstract base class for transport protocols."""

    @abstractmethod
    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a JSON-RPC request and return the response."""
        pass

    async def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of tools from the server."""
        try:
            response = await self.send_request("tools/list")
            logging.info("Raw server response: %s", response)

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
        """Call a specific tool with arguments."""
        # Apply safety filtering
        if not is_safe_tool_call(tool_name, arguments):
            safety_filter.log_blocked_operation(
                tool_name, arguments, "Dangerous tool call blocked in transport"
            )
            return create_safety_response(tool_name)

        # Sanitize arguments if needed (even if not completely blocked)
        sanitized_tool_name, sanitized_arguments = sanitize_tool_call(
            tool_name, arguments
        )

        # Check if arguments were sanitized
        safety_sanitized = sanitized_arguments != arguments

        params = {"name": sanitized_tool_name, "arguments": sanitized_arguments}
        result = await self.send_request("tools/call", params)

        # Add safety information to the result if it was sanitized
        if safety_sanitized and isinstance(result, dict):
            if "_meta" not in result:
                result["_meta"] = {}
            result["_meta"]["safety_sanitized"] = True
            result["_meta"]["original_arguments"] = arguments
            result["_meta"]["sanitized_arguments"] = sanitized_arguments

        return result


class HTTPTransport(TransportProtocol):
    """HTTP-based transport for MCP servers."""

    def __init__(
        self,
        url: str,
        timeout: float = 30.0,
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        # Add authentication headers if provided
        if auth_headers:
            self.headers.update(auth_headers)

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a JSON-RPC request via HTTP."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()

            # Try to parse as JSON first
            try:
                data = response.json()
            except json.JSONDecodeError:
                # If not JSON, try to parse as SSE
                logging.info("Response is not JSON, trying to parse as SSE")
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        try:
                            data = json.loads(line[len("data:") :].strip())
                            break
                        except json.JSONDecodeError:
                            logging.error("Failed to parse SSE data line as JSON")
                            raise
                else:
                    logging.error("No valid data: line found in SSE response")
                    raise Exception("Invalid SSE response format")

            if "error" in data:
                logging.error("Server returned error: %s", data["error"])
                raise Exception(f"Server error: {data['error']}")

            # Return the result if it exists, otherwise return the full data
            return data.get("result", data)


class SSETransport(TransportProtocol):
    """Server-Sent Events transport for MCP servers."""

    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a JSON-RPC request via SSE."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()

            # Parse SSE response
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[len("data:") :].strip())
                        if "error" in data:
                            logging.error("Server returned error: %s", data["error"])
                            raise Exception(f"Server error: {data['error']}")
                        return data.get("result", data)
                    except json.JSONDecodeError:
                        logging.error("Failed to parse SSE data line as JSON")
                        continue

            raise Exception("No valid SSE response received")


class StdioTransport(TransportProtocol):
    """Stdio-based transport for MCP servers."""

    def __init__(self, command: str, timeout: float = 30.0):
        self.command = command
        self.timeout = timeout

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a JSON-RPC request via stdio."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        # Run the command with the request as stdin
        process = await asyncio.create_subprocess_exec(
            *shlex.split(self.command),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdin_data = (
            json.dumps(payload).encode() + b"\n"
        )  # Add newline to ensure input is sent
        stdout, stderr = await asyncio.wait_for(
            process.communicate(stdin_data), timeout=self.timeout
        )

        if process.returncode != 0:
            logging.error(
                "Process failed with return code %d: %s",
                process.returncode,
                stderr.decode(),
            )
            raise Exception(f"Process failed: {stderr.decode()}")

        # Parse the response
        stdout_text = stdout.decode()
        stderr_text = stderr.decode()

        logging.debug("Process stdout: %s", stdout_text)
        logging.debug("Process stderr: %s", stderr_text)

        try:
            # Handle multiple JSON objects in the response
            # Split by newlines and try to parse each line as JSON
            lines = stdout_text.strip().split("\n")
            main_response = None

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                try:
                    json_obj = json.loads(line)

                    # Skip notification messages
                    if json_obj.get("method") == "notifications/message":
                        continue

                    # Look for the main response (has "result" or "error" field)
                    if "result" in json_obj or "error" in json_obj:
                        main_response = json_obj
                        break

                except json.JSONDecodeError:
                    # Skip lines that aren't valid JSON
                    continue

            if main_response is None:
                # If no main response found, raise JSONDecodeError
                raise json.JSONDecodeError("No main response found", stdout_text, 0)
            else:
                data = main_response

            if "error" in data:
                logging.error("Server returned error: %s", data["error"])
                raise Exception(f"Server error: {data['error']}")
            return data.get("result", data)
        except json.JSONDecodeError:
            logging.error("Failed to parse response as JSON: %s", stdout_text)
            logging.error("Process stderr: %s", stderr_text)
            raise


class WebSocketTransport(TransportProtocol):
    """WebSocket-based transport for MCP servers."""

    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a JSON-RPC request via WebSocket."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        async with websockets.connect(self.url) as websocket:
            await websocket.send(json.dumps(payload))

            try:
                response = await asyncio.wait_for(
                    websocket.recv(), timeout=self.timeout
                )
                data = json.loads(response)

                if "error" in data:
                    logging.error("Server returned error: %s", data["error"])
                    raise Exception(f"Server error: {data['error']}")

                return data.get("result", data)
            except asyncio.TimeoutError:
                raise Exception("WebSocket request timed out")


def create_transport(protocol: str, endpoint: str, **kwargs) -> TransportProtocol:
    """Factory function to create the appropriate transport based on protocol."""
    if protocol == "http":
        return HTTPTransport(endpoint, **kwargs)
    elif protocol == "sse":
        return SSETransport(endpoint, **kwargs)
    elif protocol == "stdio":
        return StdioTransport(endpoint, **kwargs)
    elif protocol == "websocket":
        return WebSocketTransport(endpoint, **kwargs)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")
