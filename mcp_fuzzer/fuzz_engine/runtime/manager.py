#!/usr/bin/env python3
"""
Process Manager for MCP Fuzzer Runtime

This module provides process management functionality with fully
async operations.
"""

import asyncio
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .watchdog import ProcessWatchdog, WatchdogConfig


@dataclass
class ProcessConfig:
    """Configuration for a managed process."""

    command: List[str]
    cwd: Optional[Union[str, Path]] = None
    env: Optional[Dict[str, str]] = None
    timeout: float = 30.0
    auto_kill: bool = True
    name: str = "unknown"
    activity_callback: Optional[Callable[[], float]] = None

    @classmethod
    def from_config(cls, config: Dict[str, Any], **overrides) -> "ProcessConfig":
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
        config: Optional[WatchdogConfig] = None,
        config_dict: Optional[Dict[str, Any]] = None
    ):
        """Initialize the async process manager."""
        if config_dict:
            self.config = WatchdogConfig.from_config(config_dict)
        else:
            self.config = config or WatchdogConfig()
        self.watchdog = ProcessWatchdog(self.config)
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger(__name__)

    async def start_process(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        """Start a new process asynchronously."""
        try:
            # Ensure watchdog monitoring is running
            await self.watchdog.start()

            # Start the process using asyncio subprocess
            cwd = str(config.cwd) if isinstance(config.cwd, Path) else config.cwd
            env = (
                {**os.environ, **(config.env or {})}
                if config.env is not None
                else os.environ.copy()
            )

            # Start the process with asyncio
            process = await asyncio.create_subprocess_exec(
                *config.command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=(os.name != "nt"),
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )

            # Register with watchdog
            await self.watchdog.register_process(
                process.pid, process, config.activity_callback, config.name
            )

            # Store process info
            async with self._lock:
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

        except Exception as e:
            self._logger.error(f"Failed to start process {config.name}: {e}")
            raise

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        """Stop a running process asynchronously."""
        async with self._lock:
            if pid not in self._processes:
                return False

            process_info = self._processes[pid]
            process = process_info["process"]
            name = process_info["config"].name

        try:
            if force:
                # Force kill
                await self._force_kill_process(pid, process, name)
            else:
                # Graceful termination
                await self._graceful_terminate_process(pid, process, name)

            # Update status to reflect stop intent
            async with self._lock:
                if pid in self._processes:
                    self._processes[pid]["status"] = "stopped"

            # Unregister from watchdog
            await self.watchdog.unregister_process(pid)

            return True

        except Exception as e:
            self._logger.error(f"Failed to stop process {pid} ({name}): {e}")
            return False

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
            await asyncio.wait_for(process.wait(), timeout=1.0)
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
            await asyncio.wait_for(process.wait(), timeout=2.0)
            self._logger.info(f"Gracefully stopped process {pid} ({name})")
        except asyncio.TimeoutError:
            # Escalate to kill and ensure we reap to avoid zombies
            self._logger.info(f"Escalating to SIGKILL for process {pid} ({name})")
            await self._force_kill_process(pid, process, name)

    async def stop_all_processes(self, force: bool = False) -> None:
        """Stop all running processes asynchronously."""
        # Snapshot PIDs under lock to avoid concurrent mutation during iteration
        async with self._lock:
            pids = list(self._processes.keys())
        tasks = [self.stop_process(pid, force=force) for pid in pids]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get status information for a specific process."""
        async with self._lock:
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

    async def list_processes(self) -> List[Dict[str, Any]]:
        """Get a list of all managed processes with their status."""
        # Copy current PIDs under lock, then fetch statuses outside to avoid
        # re-entrant lock acquisition in get_process_status
        async with self._lock:
            pids = list(self._processes.keys())

        results = await asyncio.gather(
            *(self.get_process_status(pid) for pid in pids),
            return_exceptions=True,
        )
        # Filter out None and any exceptions
        filtered: List[Dict[str, Any]] = [r for r in results if isinstance(r, dict)]
        return filtered

    async def wait_for_process(
        self, pid: int, timeout: Optional[float] = None
    ) -> Optional[int]:
        """Wait for a process to complete asynchronously."""
        async with self._lock:
            if pid not in self._processes:
                return None

            process = self._processes[pid]["process"]

        try:
            if timeout is None:
                await process.wait()
            else:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            return process.returncode
        except asyncio.TimeoutError:
            # Process didn't complete within timeout, return current status
            return process.returncode

    async def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        await self.watchdog.update_activity(pid)

    async def get_stats(self) -> Dict[str, Any]:
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
        async with self._lock:
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
        async with self._lock:
            self._processes.clear()
        self._logger.info("Process manager shutdown complete")

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        """Send a timeout signal to a running process asynchronously."""
        async with self._lock:
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

        except Exception as e:
            self._logger.error(
                f"Failed to send {signal_type} signal to process {pid} ({name}): {e}"
            )
            return False

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
    ) -> Dict[int, bool]:
        """Send a timeout signal to all running processes asynchronously."""
        results = {}
        async with self._lock:
            pids = list(self._processes.keys())

        tasks = [self.send_timeout_signal(pid, signal_type) for pid in pids]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for pid, result in zip(pids, results_list):
            if isinstance(result, Exception):
                results[pid] = False
            else:
                results[pid] = result

        return results

    async def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered with the watchdog."""
        return await self.watchdog.is_process_registered(pid)

    async def register_existing_process(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        name: str,
        activity_callback: Optional[Callable[[], float]] = None,
    ) -> None:
        """Register an already-started subprocess with the manager and watchdog."""
        # Register with watchdog first
        await self.watchdog.register_process(pid, process, activity_callback, name)

        # Track in manager table
        async with self._lock:
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
