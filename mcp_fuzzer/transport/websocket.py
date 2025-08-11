import asyncio
import uuid
import json
from typing import Any, Dict, Optional

import websockets

from .base import TransportProtocol


class WebSocketTransport(TransportProtocol):
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
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
                if isinstance(data, dict) and "error" in data:
                    raise Exception(f"Server error: {data['error']}")
                if isinstance(data, dict):
                    return data.get("result", data)
                return data
            except asyncio.TimeoutError:
                raise Exception("WebSocket request timed out")

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        async with websockets.connect(self.url) as websocket:
            await websocket.send(json.dumps(payload))
            try:
                response = await asyncio.wait_for(
                    websocket.recv(), timeout=self.timeout
                )
                data = json.loads(response)
                if isinstance(data, dict) and "error" in data:
                    raise Exception(f"Server error: {data['error']}")
                if isinstance(data, dict):
                    return data.get("result", data)
                return data
            except asyncio.TimeoutError:
                raise Exception("WebSocket request timed out")

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        async with websockets.connect(self.url) as websocket:
            await websocket.send(json.dumps(payload))
