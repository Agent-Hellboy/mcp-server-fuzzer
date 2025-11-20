#!/usr/bin/env python3
"""Process connection management for stdio transport."""

import asyncio
import logging
import os
import signal as _signal
import subprocess
import sys
import time
from typing import Any, Optional

from ..exceptions import ProcessStartError

from ..fuzz_engine.runtime import ProcessManager, WatchdogConfig
from ..safety_system.policy import sanitize_subprocess_env


class ProcessConnectionManager:
    """Manages subprocess connection lifecycle for stdio transport."""

    def __init__(self, command: str, timeout: float = 30.0):
        self.command = command
        self.timeout = timeout
        self.process: Optional[subprocess.Popen] = None
        self.stdin: Optional[Any] = None
        self.stdout: Optional[Any] = None
        self.stderr: Optional[Any] = None
        self._lock = asyncio.Lock()
        self._initialized = False
        self._last_activity = time.time()

        # Initialize process manager
        watchdog_config = WatchdogConfig(
            check_interval=1.0,
            process_timeout=self.timeout,
            extra_buffer=5.0,
            max_hang_time=self.timeout + 10.0,
            auto_kill=True,
        )
        self.process_manager = ProcessManager(watchdog_config)

    async def get_stats(self) -> dict[str, Any]:
        """Aggregate stats from the connection and underlying process manager."""
        process_stats = self.get_process_stats()
        try:
            manager_stats = await self.process_manager.get_stats()
        except Exception as exc:  # pragma: no cover - defensive logging
            logging.warning("Failed to gather process manager stats: %s", exc)
            manager_stats = None

        stats = {"process": process_stats}
        if manager_stats is not None:
            stats["manager"] = manager_stats
        return stats

    async def _update_activity(self):
        """Update last activity timestamp and notify process manager."""
        self._last_activity = time.time()
        if self.process and hasattr(self.process, "pid"):
            await self.process_manager.update_activity(self.process.pid)

    def _get_last_activity_timestamp(self) -> float:
        """Get the timestamp of last activity."""
        return self._last_activity

    async def ensure_connection(self):
        """Ensure we have a persistent connection to the subprocess."""
        # Fast-path: if already initialized and process is alive, avoid locking
        proc = self.process
        if self._initialized and proc is not None and proc.returncode is None:
            return

        async with self._lock:
            if self._initialized and self.process and self.process.returncode is None:
                return

            # Kill existing process if any
            if self.process:
                await self._stop_process()

            # Start new process
            await self._start_process()

    async def write(self, data: bytes) -> None:
        """Write to the child stdin and flush."""
        if not self.stdin:
            raise RuntimeError("stdin is not available for the managed process")

        self.stdin.write(data)
        await self.stdin.drain()
        await self._update_activity()

    async def readline(self) -> bytes:
        """Read a line from the child stdout."""
        if not self.stdout:
            return b""

        line = await self.stdout.readline()
        await self._update_activity()
        return line

    async def _start_process(self):
        """Start the subprocess and set up communication streams."""
        try:
            # Parse command with shell support for complex commands
            if isinstance(self.command, str):
                # Use shlex to properly parse command strings
                import shlex
                args = shlex.split(self.command)
            else:
                args = self.command

            # Create sanitized environment
            env = sanitize_subprocess_env()

            # Start process with proper signal handling
            if sys.platform == "win32":
                # Windows: CREATE_NEW_PROCESS_GROUP
                self.process = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    text=True,
                    encoding='utf-8',
                )
            else:
                # Unix-like: Create new process group
                self.process = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    preexec_fn=os.setsid,
                    text=True,
                    encoding='utf-8',
                )

            self.stdin = self.process.stdin
            self.stdout = self.process.stdout
            self.stderr = self.process.stderr

            # Register with process manager
            if hasattr(self.process, "pid"):
                await self.process_manager.start_process(self.process.pid)

            self._initialized = True
            await self._update_activity()

        except (OSError, ValueError, subprocess.SubprocessError) as e:
            error_msg = f"Failed to start process '{self.command}': {e}"
            logging.error(error_msg)
            raise ProcessStartError(error_msg, context={"command": self.command}) from e

    async def _stop_process(self):
        """Stop the current process gracefully."""
        if not self.process:
            return

        try:
            if hasattr(self.process, "pid"):
                await self.process_manager.stop_process(self.process.pid, force=True)
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

        self.process = None
        self.stdin = None
        self.stdout = None
        self.stderr = None
        self._initialized = False

    async def send_signal(self, signal_type: str, pid: Optional[int] = None) -> bool:
        """Send a signal to the process via the watchdog or directly."""
        process = self.process
        if not process:
            return False

        target_pid = pid or process.pid
        if not target_pid:
            return False

        try:
            if await self.process_manager.is_process_registered(target_pid):
                return await self.process_manager.send_timeout_signal(
                    target_pid, signal_type
                )
        except Exception as exc:
            logging.warning(
                "Failed to send signal via process manager for %s: %s",
                target_pid,
                exc,
            )

        try:
            if signal_type == "timeout":
                # Send timeout signal
                if sys.platform == "win32":
                    try:
                        os.kill(target_pid, _signal.CTRL_BREAK_EVENT)
                    except (AttributeError, ValueError):
                        os.kill(target_pid, _signal.SIGKILL)
                else:
                    try:
                        pgid = os.getpgid(target_pid)
                        os.killpg(pgid, _signal.SIGKILL)
                    except OSError:
                        os.kill(target_pid, _signal.SIGKILL)
            elif signal_type == "force":
                os.kill(target_pid, _signal.SIGKILL)
            elif signal_type == "interrupt":
                if sys.platform == "win32":
                    os.kill(target_pid, _signal.CTRL_C_EVENT)
                else:
                    os.kill(target_pid, _signal.SIGINT)
            else:
                logging.warning(f"Unknown signal type: {signal_type}")
                return False
        except (OSError, ProcessLookupError) as e:
            logging.warning(
                f"Failed to send signal {signal_type} to process {target_pid}: {e}"
            )
            return False

        return True

    def get_process_stats(self) -> dict[str, Any]:
        """Get statistics about the current process."""
        stats = {
            "command": self.command,
            "timeout": self.timeout,
            "initialized": self._initialized,
            "last_activity": self._last_activity,
            "active": False,
            "process_id": None,
        }

        if self.process:
            stats.update({
                "process_id": self.process.pid,
                "returncode": self.process.returncode,
                "active": self.process.returncode is None,
            })

        return stats

    async def cleanup(self):
        """Clean up resources."""
        if self.process:
            await self._stop_process()
        await self.process_manager.cleanup()
