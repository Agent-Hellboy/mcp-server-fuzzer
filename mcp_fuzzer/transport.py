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


class TransportProtocol(ABC):
    """Abstract base class for transport protocols."""
    
    @abstractmethod
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC request and return the response."""
        pass
    
    async def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of tools from the server."""
        try:
            response = await self.send_request("tools/list")
            logging.info("Raw server response: %s", response)
            
            if not isinstance(response, dict):
                logging.warning("Server response is not a dictionary. Got type: %s", type(response))
                return []
            
            if "tools" not in response:
                logging.warning("Server response missing 'tools' key. Keys present: %s", list(response.keys()))
                return []
            
            tools = response["tools"]
            logging.info("Found %d tools from server", len(tools))
            return tools
            
        except Exception as e:
            logging.exception("Failed to fetch tools from server: %s", e)
            return []
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a specific tool with arguments."""
        params = {"name": tool_name, "arguments": arguments}
        return await self.send_request("tools/call", params)


class HTTPTransport(TransportProtocol):
    """HTTP-based transport for MCP servers."""
    
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
    
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
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
                            data = json.loads(line[len("data:"):].strip())
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
    
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
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
                        data = json.loads(line[len("data:"):].strip())
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
    
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
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
            stderr=asyncio.subprocess.PIPE
        )
        
        stdin_data = json.dumps(payload).encode() + b'\n'  # Add newline to ensure input is sent
        stdout, stderr = await asyncio.wait_for(
            process.communicate(stdin_data),
            timeout=self.timeout
        )
        
        if process.returncode != 0:
            logging.error("Process failed with return code %d: %s", process.returncode, stderr.decode())
            raise Exception(f"Process failed: {stderr.decode()}")
        
        # Parse the response
        stdout_text = stdout.decode()
        stderr_text = stderr.decode()
        
        logging.debug("Process stdout: %s", stdout_text)
        logging.debug("Process stderr: %s", stderr_text)
        
        try:
            data = json.loads(stdout_text)
            if "error" in data:
                logging.error("Server returned error: %s", data["error"])
                raise Exception(f"Server error: {data['error']}")
            return data.get("result", data)
        except json.JSONDecodeError:
            logging.error("Failed to parse response as JSON: %s", stdout_text)
            logging.error("Process stderr: %s", stderr_text)
            raise Exception("Invalid JSON response")


class WebSocketTransport(TransportProtocol):
    """WebSocket-based transport for MCP servers."""
    
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
    
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
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
                response = await asyncio.wait_for(websocket.recv(), timeout=self.timeout)
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