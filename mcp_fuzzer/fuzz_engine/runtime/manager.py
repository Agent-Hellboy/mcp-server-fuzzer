#!/usr/bin/env python3
"""
Process Manager for MCP Fuzzer Runtime

This module provides process management functionality with fully
async operations.
"""

import asyncio
import inspect
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ...exceptions import (
    MCPError,
    ProcessSignalError,
    ProcessStartError,
    ProcessStopError,
)
from .watchdog import ProcessWatchdog, WatchdogConfig


@dataclass
class ProcessConfig:
    """Configuration for a managed process."""

    command: list[str]
    cwd: str | Path | None = None
    env: dict[str, str] | None = None
    timeout: float = 30.0
    auto_kill: bool = True
    name: str = "unknown"
    activity_callback: Callable[[], float] | None = None

    @classmethod
    def from_config(cls, config: dict[str, Any], **overrides) -> "ProcessConfig":
        """Create ProcessConfig with values from configuration dictionary."""
        return cls(
            timeout=config.get("process_timeout", 30.0),
            auto_kill=config.get("auto_kill", True),
            **overrides
        )


class ProcessManager:
    """Fully asynchronous process manager."""

    def __init__(
        self,
        config: WatchdogConfig | None = None,
        config_dict: dict[str, Any] | None = None
    ):
        """Initialize the async process manager."""
        if config_dict:
            self.config = WatchdogConfig.from_config(config_dict)
        else:
            self.config = config or WatchdogConfig()
        self.watchdog = ProcessWatchdog(self.config)
        self._processes: dict[int, dict[str, Any]] = {}
        self._lock = None  # Will be created lazily when needed
        self._logger = logging.getLogger(__name__)

    def _get_lock(self):
        """Get or create the lock lazily."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @staticmethod
    def _normalize_returncode(value: Any) -> int | None:
        """Return an integer returncode or None, ignore mock objects."""
        if value is None or isinstance(value, int):
            return value
        return None

    @staticmethod
    def _format_output(data: Any) -> str:
        """Convert process output into a readable string."""
        if data is None:
            return ""
        if isinstance(data, bytes):
            return data.decode(errors="replace").strip()
        if isinstance(data, str):
            return data.strip()
        return str(data).strip()

    async def _wait_for_process_exit(
        self, process: asyncio.subprocess.Process, timeout: float | None = None
    ) -> Any:
        """Await process.wait() while tolerating mocked/synchronous implementations."""
        wait_result = process.wait()
        if inspect.isawaitable(wait_result):
            if timeout is None:
                return await wait_result
            return await asyncio.wait_for(wait_result, timeout=timeout)
        # For MagicMock/synchronous waits, return immediately
        return wait_result

    async def start_process(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        """Start a new process asynchronously."""
        # Prepare execution context for better diagnostics if startup fails
        cwd = str(config.cwd) if isinstance(config.cwd, Path) else config.cwd
        env = (
            {**os.environ, **(config.env or {})}
            if config.env is not None
            else os.environ.copy()
        )

        try:
            # Ensure watchdog monitoring is running
            await self.watchdog.start()

            # Start the process with asyncio
            process = await asyncio.create_subprocess_exec(
                *config.command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=(os.name != "nt"),
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
            await asyncio.sleep(0.1)
            
            # Check if process died immediately otherwise 
            # stdio stream reading will make it blocking 
            returncode = self._normalize_returncode(process.returncode)
            if returncode is not None:
                # Process exited, read its output to provide diagnostic info
                stderr = await process.stderr.read()
                stdout = await process.stdout.read()

                error_output = (
                    self._format_output(stderr)
                    or self._format_output(stdout)
                    or "No output"
                )
                raise ProcessStartError(
                    (
                        f"Process {config.name} exited with code "
                        f"{returncode}: {error_output}"
                    ),
                    context={
                        "command": config.command, 
                        "cwd": cwd, 
                        "env": env,
                        "returncode": returncode,
                        "stderr": self._format_output(stderr),
                        "stdout": self._format_output(stdout)
                    }
                )
            
            # Process is running, continue normally
            # Register with watchdog
            await self.watchdog.register_process(
                process.pid, process, config.activity_callback, config.name
            )

            # Store process info
            async with self._get_lock():
                self._processes[process.pid] = {
                    "process": process,
                    "config": config,
                    "started_at": time.time(),
                    "status": "running",
                }

            self._logger.info(
                f"Started process {process.pid} ({config.name}): "
                f"{' '.join(config.command)}"
            )
            return process

        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to start process {config.name}: {e}")
            raise ProcessStartError(
                f"Failed to start process {config.name}",
                context={
                    "name": config.name,
                    "command": config.command,
                    "cwd": cwd,
                },
            ) from e

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        """Stop a running process asynchronously."""
        async with self._get_lock():
            if pid not in self._processes:
                return False

            process_info = self._processes[pid]
            process = process_info["process"]
            name = process_info["config"].name
        try:
            returncode = self._normalize_returncode(process.returncode)
            if returncode is not None:
                self._logger.debug(
                    "Process %s (%s) already exited with code %s",
                    pid,
                    name,
                    returncode,
                )
                async with self._get_lock():
                    if pid in self._processes:
                        self._processes[pid]["status"] = "stopped"
                    await self.watchdog.unregister_process(pid)
                    return True
            if force:
                # Force kill
                await self._force_kill_process(pid, process, name)
            else:
                # Graceful termination
                await self._graceful_terminate_process(pid, process, name)

            # Update status to reflect stop intent
            async with self._get_lock():
                if pid in self._processes:
                    self._processes[pid]["status"] = "stopped"

            # Unregister from watchdog
            await self.watchdog.unregister_process(pid)

            return True

        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to stop process {pid} ({name}): {e}")
            raise ProcessStopError(
                f"Failed to stop process {pid} ({name})",
                context={"pid": pid, "force": force, "name": name},
            ) from e

    async def _force_kill_process(
        self, pid: int, process: asyncio.subprocess.Process, name: str
    ) -> None:
        """Force kill a process."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                process.kill()
            self._logger.info(f"Force killed process {pid} ({name})")
        else:
            process.kill()
            self._logger.info(f"Force killed process {pid} ({name})")

        # Wait for the process to actually terminate
        try:
            await self._wait_for_process_exit(process, timeout=1.0)
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Process {pid} ({name}) didn't respond to kill signal"
            )

    async def _graceful_terminate_process(
        self, pid: int, process: asyncio.subprocess.Process, name: str
    ) -> None:
        """Gracefully terminate a process."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
            except OSError:
                process.terminate()
        else:
            process.terminate()

        # Give process a short window to terminate gracefully
        try:
            await self._wait_for_process_exit(process, timeout=2.0)
            self._logger.info(f"Gracefully stopped process {pid} ({name})")
        except asyncio.TimeoutError:
            # Escalate to kill and ensure we reap to avoid zombies
            self._logger.info(f"Escalating to SIGKILL for process {pid} ({name})")
            await self._force_kill_process(pid, process, name)

    async def stop_all_processes(self, force: bool = False) -> None:
        """Stop all running processes asynchronously."""
        # Snapshot PIDs under lock to avoid concurrent mutation during iteration
        async with self._get_lock():
            pids = list(self._processes.keys())
        tasks = [self.stop_process(pid, force=force) for pid in pids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        failures: list[dict[str, Any]] = []
        for pid, result in zip(pids, results):
            if isinstance(result, Exception):
                failures.append(
                    {"pid": pid, "error": type(result).__name__, "message": str(result)}
                )
            elif result is False:
                failures.append({"pid": pid, "error": None, "message": "not found"})

        if failures:
            raise ProcessStopError(
                "Failed to stop all managed processes",
                context={"failed_processes": failures},
            )

    async def get_process_status(self, pid: int) -> dict[str, Any] | None:
        """Get status information for a specific process."""
        async with self._get_lock():
            if pid not in self._processes:
                return None

            process_info = self._processes[pid].copy()
            process = process_info["process"]

            # Add current process state
            if process.returncode is None:
                process_info["status"] = "running"
            else:
                process_info["status"] = "finished"
                process_info["exit_code"] = process.returncode

            return process_info

    async def list_processes(self) -> list[dict[str, Any]]:
        """Get a list of all managed processes with their status."""
        # Copy current PIDs under lock, then fetch statuses outside to avoid
        # re-entrant lock acquisition in get_process_status
        async with self._get_lock():
            pids = list(self._processes.keys())

        results = await asyncio.gather(
            *(self.get_process_status(pid) for pid in pids),
            return_exceptions=True,
        )
        # Filter out None and any exceptions
        filtered: list[dict[str, Any]] = [r for r in results if isinstance(r, dict)]
        return filtered

    async def wait_for_process(
        self, pid: int, timeout: float | None = None
    ) -> int | None:
        """Wait for a process to complete asynchronously."""
        async with self._get_lock():
            if pid not in self._processes:
                return None

            process = self._processes[pid]["process"]

        try:
            if timeout is None:
                await self._wait_for_process_exit(process)
            else:
                await self._wait_for_process_exit(process, timeout=timeout)
            return process.returncode
        except asyncio.TimeoutError:
            # Process didn't complete within timeout, return current status
            return process.returncode

    async def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        await self.watchdog.update_activity(pid)

    async def get_stats(self) -> dict[str, Any]:
        """Get overall statistics about managed processes."""
        process_stats = await self.list_processes()
        watchdog_stats = await self.watchdog.get_stats()

        # Count processes by status
        status_counts = {}
        for proc in process_stats:
            status = proc.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "processes": status_counts,
            "watchdog": watchdog_stats,
            "total_managed": len(process_stats),
        }

    async def cleanup_finished_processes(self) -> int:
        """Remove finished processes from tracking and return count cleaned."""
        cleaned = 0
        async with self._get_lock():
            pids_to_remove = []
            for pid, process_info in self._processes.items():
                process = process_info["process"]
                if process.returncode is not None:
                    pids_to_remove.append(pid)

            for pid in pids_to_remove:
                del self._processes[pid]
                await self.watchdog.unregister_process(pid)
                cleaned += 1

        if cleaned > 0:
            self._logger.debug(f"Cleaned up {cleaned} finished processes")

        return cleaned

    async def shutdown(self) -> None:
        """Shutdown the process manager and stop all processes."""
        self._logger.info("Shutting down process manager")
        await self.stop_all_processes()
        await self.watchdog.stop()

        # Clear process tracking to free memory
        async with self._get_lock():
            self._processes.clear()
        self._logger.info("Process manager shutdown complete")

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        """Send a timeout signal to a running process asynchronously."""
        async with self._get_lock():
            if pid not in self._processes:
                return False

            process_info = self._processes[pid]
            process = process_info["process"]
            name = process_info["config"].name

        try:
            if process.returncode is not None:
                # Process already finished
                return False

            # Send appropriate signal based on type
            if signal_type == "timeout":
                await self._send_term_signal(pid, process, name)
            elif signal_type == "force":
                await self._send_kill_signal(pid, process, name)
            elif signal_type == "interrupt":
                await self._send_interrupt_signal(pid, process, name)
            else:
                self._logger.warning(f"Unknown signal type: {signal_type}")
                return False

            return True

        except MCPError:
            raise
        except Exception as e:
            self._logger.error(
                f"Failed to send {signal_type} signal to process {pid} ({name}): {e}"
            )
            raise ProcessSignalError(
                f"Failed to send {signal_type} signal to process {pid} ({name})",
                context={"pid": pid, "signal_type": signal_type, "name": name},
            ) from e

    async def _send_term_signal(
        self, pid: int, process: asyncio.subprocess.Process, name: str
    ) -> None:
        """Send SIGTERM signal to process."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
                self._logger.info(f"Sent SIGTERM signal to process {pid} ({name})")
            except OSError:
                process.terminate()
                self._logger.info(f"Sent terminate signal to process {pid} ({name})")
        else:
            process.terminate()
            self._logger.info(f"Sent terminate signal to process {pid} ({name})")

    async def _send_kill_signal(
        self, pid: int, process: asyncio.subprocess.Process, name: str
    ) -> None:
        """Send SIGKILL signal to process."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
                self._logger.info(f"Sent SIGKILL signal to process {pid} ({name})")
            except OSError:
                process.kill()
                self._logger.info(f"Sent kill signal to process {pid} ({name})")
        else:
            process.kill()
            self._logger.info(f"Sent kill signal to process {pid} ({name})")

    async def _send_interrupt_signal(
        self, pid: int, process: asyncio.subprocess.Process, name: str
    ) -> None:
        """Send SIGINT signal to process."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGINT)
                self._logger.info(f"Sent SIGINT to process group {pid} ({name})")
            except OSError:
                os.kill(pid, signal.SIGINT)
                self._logger.info(f"Sent SIGINT to process {pid} ({name})")
        else:
            try:
                os.kill(pid, signal.CTRL_BREAK_EVENT)
                self._logger.info(
                    f"Sent CTRL_BREAK_EVENT to process/group {pid} ({name})"
                )
            except OSError:
                process.terminate()
                self._logger.info(f"Sent terminate signal to process {pid} ({name})")

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> dict[int, bool]:
        """Send a timeout signal to all running processes asynchronously."""
        results: dict[int, bool] = {}
        async with self._get_lock():
            pids = list(self._processes.keys())

        tasks = [self.send_timeout_signal(pid, signal_type) for pid in pids]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        failures: list[dict[str, Any]] = []
        for pid, result in zip(pids, results_list):
            if isinstance(result, Exception):
                failures.append(
                    {"pid": pid, "error": type(result).__name__, "message": str(result)}
                )
                results[pid] = False
            else:
                results[pid] = bool(result)

        if failures:
            raise ProcessSignalError(
                f"Failed to send {signal_type} signal to some processes",
                context={"signal_type": signal_type, "failed_processes": failures},
            )

        return results

    async def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered with the watchdog."""
        return await self.watchdog.is_process_registered(pid)

    async def register_existing_process(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        name: str,
        activity_callback: Callable[[], float] | None = None,
    ) -> None:
        """Register an already-started subprocess with the manager and watchdog."""
        # Register with watchdog first
        await self.watchdog.register_process(pid, process, activity_callback, name)

        # Track in manager table
        async with self._get_lock():
            self._processes[pid] = {
                "process": process,
                "config": ProcessConfig(
                    command=[name],
                    name=name,
                    activity_callback=activity_callback,
                ),
                "started_at": time.time(),
                "status": "running",
            }
