import json
import logging
import uuid
import time
from typing import Any, Dict, Optional

import httpx

from .base import TransportProtocol
from ..fuzz_engine.runtime import ProcessManager, WatchdogConfig


class HTTPTransport(TransportProtocol):
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
        if auth_headers:
            self.headers.update(auth_headers)

        # Track last activity for process management
        self._last_activity = time.time()

        # Initialize process manager for any subprocesses (like proxy servers)
        watchdog_config = WatchdogConfig(
            check_interval=1.0,
            process_timeout=timeout,
            extra_buffer=5.0,
            max_hang_time=timeout + 10.0,
            auto_kill=True,
        )
        self.process_manager = ProcessManager(watchdog_config)

    def _update_activity(self):
        """Update last activity timestamp."""
        self._last_activity = time.time()

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        self._update_activity()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            try:
                data = response.json()
            except json.JSONDecodeError:
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
            if isinstance(data, dict) and "error" in data:
                logging.error("Server returned error: %s", data["error"])
                raise Exception(f"Server error: {data['error']}")
            if isinstance(data, dict):
                return data.get("result", data)
            return data

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        self._update_activity()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            try:
                data = response.json()
            except json.JSONDecodeError:
                for line in response.text.splitlines():
                    if line.startswith("data:"):
                        data = json.loads(line[len("data:") :].strip())
                        break
                else:
                    raise
            if isinstance(data, dict) and "error" in data:
                raise Exception(f"Server error: {data['error']}")
            if isinstance(data, dict):
                return data.get("result", data)
            return data

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}}

        self._update_activity()

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()

    async def get_process_stats(self) -> Dict[str, Any]:
        """Get statistics about any managed processes."""
        return await self.process_manager.get_stats()

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> Dict[int, bool]:
        """Send timeout signals to all managed processes."""
        return await self.process_manager.send_timeout_signal_to_all(signal_type)

    async def close(self):
        """Close the transport and cleanup resources."""
        try:
            if hasattr(self, "process_manager"):
                await self.process_manager.shutdown()
        except Exception as e:
            logging.warning(f"Error shutting down HTTP transport process manager: {e}")

    def __del__(self):
        """Cleanup when the object is destroyed."""
        # Don't try to call async methods in destructor
        # The object will be cleaned up by Python's garbage collector
        pass
