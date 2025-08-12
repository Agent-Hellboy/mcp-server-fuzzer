import asyncio
import json
import uuid
import logging
import os
import shlex
import subprocess
import signal as _signal
import sys

import time
from typing import Any, Dict, Optional

from .base import TransportProtocol
from ..fuzz_engine.runtime import ProcessManager, ProcessConfig, WatchdogConfig


class StdioTransport(TransportProtocol):
    def __init__(self, command: str, timeout: float = 30.0):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self._lock = asyncio.Lock()
        self._initialized = False

        # Use our new Process Management system
        watchdog_config = WatchdogConfig(
            check_interval=1.0,
            process_timeout=timeout,
            extra_buffer=5.0,
            max_hang_time=timeout + 10.0,
            auto_kill=True,
        )
        self.process_manager = ProcessManager(watchdog_config)
        self._last_activity = time.time()

    def _update_activity(self):
        """Update last activity timestamp and notify process manager."""
        self._last_activity = time.time()
        if self.process and hasattr(self.process, "pid"):
            # Don't await here since this is a sync method
            # The activity will be updated when needed
            pass

    async def _ensure_connection(self):
        """Ensure we have a persistent connection to the subprocess."""
        # Fast-path: if already initialized and process is alive, avoid locking
        proc = self.process
        if self._initialized and proc is not None and proc.poll() is None:
            return

        async with self._lock:
            if self._initialized and self.process and self.process.poll() is None:
                return

            # Kill existing process if any
            if self.process:
                try:
                    # Use process manager to stop the process
                    if hasattr(self.process, "pid"):
                        await self.process_manager.stop_process(
                            self.process.pid, force=True
                        )
                    else:
                        # Fallback to direct process termination
                        if sys.platform == "win32":
                            try:
                                self.process.send_signal(_signal.CTRL_BREAK_EVENT)
                            except (AttributeError, ValueError):
                                self.process.kill()
                        else:
                            try:
                                pgid = os.getpgid(self.process.pid)
                                os.killpg(pgid, _signal.SIGKILL)
                            except OSError:
                                self.process.kill()
                except Exception as e:
                    logging.warning(f"Error stopping existing process: {e}")

            # Start new process using asyncio subprocess for proper async communication
            try:
                # Parse command
                if isinstance(self.command, str):
                    cmd_parts = shlex.split(self.command)
                else:
                    cmd_parts = self.command

                # Create async subprocess
                self.process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    preexec_fn=os.setsid if sys.platform != "win32" else None,
                    creationflags=(
                        subprocess.CREATE_NEW_PROCESS_GROUP
                        if sys.platform == "win32"
                        else 0
                    ),
                )

                # Set up communication
                self.stdin = self.process.stdin
                self.stdout = self.process.stdout
                self.stderr = self.process.stderr

                # Register with process manager for monitoring
                if hasattr(self.process, "pid"):
                    config = ProcessConfig(
                        command=cmd_parts,
                        name="stdio_transport",
                        timeout=self.timeout,
                        auto_kill=True,
                        activity_callback=self._get_activity_timestamp,
                    )

                    # Register the existing process with the manager
                    self.process_manager.watchdog.register_process(
                        self.process.pid,
                        self.process,
                        config.activity_callback,
                        config.name,
                    )

                self._initialized = True
                self._update_activity()
                logging.info(
                    f"Started stdio transport process with PID: {self.process.pid}"
                )

            except Exception as e:
                logging.error(f"Failed to start stdio transport process: {e}")
                self._initialized = False
                raise

    def _get_activity_timestamp(self) -> float:
        """Callback for process manager to get last activity timestamp."""
        return self._last_activity

    async def _send_message(self, message: Dict[str, Any]) -> None:
        """Send a message to the subprocess."""
        if not self._initialized:
            await self._ensure_connection()

        try:
            message_str = json.dumps(message) + "\n"
            self.stdin.write(message_str.encode())
            await self.stdin.drain()
            self._update_activity()
        except Exception as e:
            logging.error(f"Failed to send message to stdio transport: {e}")
            self._initialized = False
            raise

    async def _receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive a message from the subprocess."""
        if not self._initialized:
            await self._ensure_connection()

        try:
            line = await self.stdout.readline()
            if not line:
                return None

            self._update_activity()
            message = json.loads(line.decode().strip())
            return message
        except Exception as e:
            logging.error(f"Failed to receive message from stdio transport: {e}")
            self._initialized = False
            raise

    async def send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Send a request and wait for response."""
        request_id = str(uuid.uuid4())
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {},
        }

        await self._send_message(message)

        # Wait for response
        while True:
            response = await self._receive_message()
            if response is None:
                raise Exception("No response received from stdio transport")

            if response.get("id") == request_id:
                if "error" in response:
                    logging.error(f"Server returned error: {response['error']}")
                    raise Exception(f"Server error: {response['error']}")
                return response.get("result", response)

    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        """Send raw payload and wait for response."""
        await self._send_message(payload)

        # Wait for response
        response = await self._receive_message()
        if response is None:
            raise Exception("No response received from stdio transport")

        if "error" in response:
            logging.error(f"Server returned error: {response['error']}")
            raise Exception(f"Server error: {response['error']}")

        return response.get("result", response)

    async def send_notification(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> None:
        """Send a notification (no response expected)."""
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        await self._send_message(message)

    async def close(self):
        """Close the transport and cleanup resources."""
        try:
            if self.process and hasattr(self.process, "pid"):
                # Unregister from process manager first
                self.process_manager.watchdog.unregister_process(self.process.pid)

                # Use process manager to stop the process
                await self.process_manager.stop_process(self.process.pid, force=True)
            elif self.process:
                # Fallback to direct process termination
                if sys.platform == "win32":
                    try:
                        self.process.send_signal(_signal.CTRL_BREAK_EVENT)
                    except (AttributeError, ValueError):
                        self.process.kill()
                else:
                    try:
                        pgid = os.getpgid(self.process.pid)
                        os.killpg(pgid, _signal.SIGKILL)
                    except OSError:
                        self.process.kill()
        except Exception as e:
            logging.warning(f"Error stopping stdio transport process: {e}")
        finally:
            self._initialized = False
            self.process = None
            self.stdin = None
            self.stdout = None
            self.stderr = None

    async def get_process_stats(self) -> Dict[str, Any]:
        """Get statistics about the managed process."""
        return await self.process_manager.get_stats()

    async def send_timeout_signal(self, signal_type: str = "timeout") -> bool:
        """Send a timeout signal to the transport process."""
        if self.process and hasattr(self.process, "pid"):
            # Check if process is registered with watchdog
            if await self.process_manager.is_process_registered(self.process.pid):
                return await self.process_manager.send_timeout_signal(
                    self.process.pid, signal_type
                )
            else:
                # Process is not in managed list, send signal directly
                try:
                    if signal_type == "timeout":
                        # Send SIGTERM (graceful termination)
                        if os.name != "nt":
                            try:
                                pgid = os.getpgid(self.process.pid)
                                os.killpg(pgid, _signal.SIGTERM)
                                logging.info(
                                    (
                                        "Sent SIGTERM timeout signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                            except OSError:
                                self.process.terminate()
                                logging.info(
                                    (
                                        "Sent terminate timeout signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                        else:
                            self.process.terminate()
                            logging.info(
                                (
                                    "Sent terminate timeout signal to process "
                                    f"{self.process.pid}"
                                )
                            )
                    elif signal_type == "force":
                        # Send SIGKILL (force kill)
                        if os.name != "nt":
                            try:
                                pgid = os.getpgid(self.process.pid)
                                os.killpg(pgid, _signal.SIGKILL)
                                logging.info(
                                    (
                                        "Sent SIGKILL force signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                            except OSError:
                                self.process.kill()
                                logging.info(
                                    (
                                        "Sent kill force signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                        else:
                            self.process.kill()
                            logging.info(
                                f"Sent kill force signal to process {self.process.pid}"
                            )
                    elif signal_type == "interrupt":
                        # Send SIGINT (interrupt)
                        if os.name != "nt":
                            try:
                                pgid = os.getpgid(self.process.pid)
                                os.killpg(pgid, _signal.SIGINT)
                                logging.info(
                                    (
                                        "Sent SIGINT interrupt signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                            except OSError:
                                self.process.terminate()
                                logging.info(
                                    (
                                        "Sent terminate interrupt signal to process "
                                        f"{self.process.pid}"
                                    )
                                )
                        else:
                            self.process.terminate()
                            logging.info(
                                (
                                    "Sent terminate interrupt signal to process "
                                    f"{self.process.pid}"
                                )
                            )
                    else:
                        logging.warning(f"Unknown signal type: {signal_type}")
                        return False

                    return True

                except Exception as e:
                    logging.error(
                        (
                            f"Failed to send {signal_type} signal to process "
                            f"{self.process.pid}: {e}"
                        )
                    )
                    return False
        return False

    # Avoid destructors for async cleanup; use close()
