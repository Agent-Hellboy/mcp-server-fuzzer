#!/usr/bin/env python3
"""
Process Watchdog for MCP Fuzzer Runtime

This module provides process monitoring functionality with fully
async operations.
"""

import asyncio
import inspect
import logging
import os
import signal as _signal
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


@dataclass
class WatchdogConfig:
    """Configuration for the process watchdog."""

    check_interval: float = 1.0  # How often to check processes (seconds)
    process_timeout: float = 30.0  # Time before process is considered hanging (seconds)
    extra_buffer: float = 5.0  # Extra time before auto-kill (seconds)
    max_hang_time: float = 60.0  # Maximum time before force kill (seconds)
    auto_kill: bool = True  # Whether to automatically kill hanging processes


class ProcessWatchdog:
    """Fully asynchronous process monitoring system."""

    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the process watchdog."""
        self.config = config or WatchdogConfig()
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger(__name__)
        self._stop_event = asyncio.Event()
        self._watchdog_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the watchdog monitoring."""
        if self._watchdog_task is None or self._watchdog_task.done():
            self._stop_event.clear()
            self._watchdog_task = asyncio.create_task(self._watchdog_loop())
            self._logger.info("Process watchdog started")

    async def stop(self) -> None:
        """Stop the watchdog monitoring."""
        if self._watchdog_task and not self._watchdog_task.done():
            self._stop_event.set()
            # Don't wait for the task to complete - just cancel it
            self._watchdog_task.cancel()
            self._watchdog_task = None
            self._logger.info("Process watchdog stopped")

    async def _watchdog_loop(self) -> None:
        """Main watchdog monitoring loop."""
        while not self._stop_event.is_set():
            try:
                await self._check_processes()
                # Use asyncio.sleep instead of time.sleep to avoid blocking
                await asyncio.sleep(self.config.check_interval)
            except Exception as e:
                self._logger.error(f"Error in watchdog loop: {e}")
                await asyncio.sleep(self.config.check_interval)

    async def _check_processes(self) -> None:
        """Check all registered processes for hanging behavior."""
        current_time = time.time()
        processes_to_remove = []

        async with self._lock:
            for pid, process_info in self._processes.items():
                try:
                    process = process_info["process"]
                    name = process_info["name"]

                    # Check if process is still running
                    if process.returncode is None:
                        # Process is running, check activity
                        last_activity = await self._get_last_activity(
                            process_info, current_time
                        )
                        time_since_activity = current_time - last_activity

                        timeout_threshold = (
                            self.config.process_timeout + self.config.extra_buffer
                        )
                        if time_since_activity > timeout_threshold:
                            # Process is hanging
                            threshold = timeout_threshold
                            self._logger.warning(
                                f"Process {pid} ({name}) hanging for "
                                f"{time_since_activity:.1f}s, "
                                f"threshold: {threshold:.1f}s"
                            )

                            if self.config.auto_kill:
                                await self._kill_process(pid, process, name)
                                processes_to_remove.append(pid)
                            elif time_since_activity > self.config.max_hang_time:
                                # Force kill if it's been too long
                                self._logger.error(
                                    f"Process {pid} ({name}) exceeded max hang time "
                                    f"({self.config.max_hang_time:.1f}s), force killing"
                                )
                                await self._kill_process(pid, process, name)
                                processes_to_remove.append(pid)
                        elif time_since_activity > self.config.process_timeout:
                            # Process is slow but not hanging yet
                            self._logger.debug(
                                f"Process {pid} ({name}) slow: "
                                f"{time_since_activity:.1f}s since last activity"
                            )
                    else:
                        # Process has finished, remove from monitoring
                        processes_to_remove.append(pid)

                except (OSError, AttributeError) as e:
                    # Process is no longer accessible
                    self._logger.debug(f"Process {pid} no longer accessible: {e}")
                    processes_to_remove.append(pid)
                except Exception as e:
                    self._logger.error(f"Error checking process {pid}: {e}")
                    processes_to_remove.append(pid)

            # Remove finished/inaccessible processes
            for pid in processes_to_remove:
                del self._processes[pid]

    async def _get_last_activity(
        self, process_info: dict, current_time: float
    ) -> float:
        """Get the last activity timestamp for a process."""
        # Try to get activity from callback first
        if process_info["activity_callback"]:
            try:
                callback = process_info["activity_callback"]
                result = callback()
                if inspect.isawaitable(result):
                    result = await result
                
                # Convert and validate timestamp
                timestamp = float(result)
                # Validate the timestamp is reasonable (not in future, not negative)
                if timestamp < 0 or timestamp > time.time() + 1:
                    self._logger.warning(
                        f"Activity callback returned invalid timestamp: {timestamp}"
                    )
                    return process_info["last_activity"]
                return timestamp
            except Exception:
                self._logger.debug(
                    "activity_callback failed; falling back to stored timestamp", 
                    exc_info=True
                )

        # Fall back to stored timestamp
        return process_info["last_activity"]

    async def _kill_process(self, pid: int, process: Any, name: str) -> None:
        """Kill a hanging process."""
        try:
            self._logger.info(f"Attempting to kill hanging process {pid} ({name})")

            if sys.platform == "win32":
                # Windows: try graceful termination first
                process.terminate()
                try:
                    # Give it a moment to terminate gracefully
                    await asyncio.wait_for(process.wait(), timeout=0.5)
                    self._logger.info(
                        f"Gracefully terminated Windows process {pid} ({name})"
                    )
                except asyncio.TimeoutError:
                    # Process still running, force kill
                    process.kill()
                    self._logger.info(f"Force killed Windows process {pid} ({name})")
            else:
                # Unix-like systems: try SIGTERM first, then SIGKILL
                try:
                    # Send SIGTERM for graceful shutdown
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, _signal.SIGTERM)

                    try:
                        # Wait a bit for graceful shutdown
                        await asyncio.wait_for(process.wait(), timeout=0.5)
                        action = "Gracefully terminated"
                        msg = f"{action} Unix process {pid} ({name}) with SIGTERM"
                        self._logger.info(msg)
                    except asyncio.TimeoutError:
                        # Process still running, force kill with SIGKILL
                        try:
                            os.killpg(pgid, _signal.SIGKILL)
                            self._logger.info(
                                f"Force killed Unix process {pid} ({name}) with SIGKILL"
                            )
                        except OSError:
                            # Fallback to process.kill()
                            process.kill()
                            action = "Force killed"
                            method = "process.kill()"
                            msg = f"{action} Unix process {pid} ({name}) with {method}"
                            self._logger.info(msg)
                except OSError:
                    # Process group not accessible, try direct process termination
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=0.5)
                        action = "Gracefully terminated"
                        method = "process.terminate()"
                        msg = f"{action} Unix process {pid} ({name}) with {method}"
                        self._logger.info(msg)
                    except asyncio.TimeoutError:
                        # Still running, force kill
                        process.kill()
                        action = "Force killed"
                        method = "process.kill()"
                        msg = f"{action} Unix process {pid} ({name}) with {method}"
                        self._logger.info(msg)

            # Ensure the process is reaped
            try:
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                self._logger.warning(
                    f"Process {pid} ({name}) did not exit after kill within 1.0s"
                )

            self._logger.info(f"Successfully killed hanging process {pid} ({name})")

        except Exception as e:
            self._logger.error(f"Failed to kill process {pid} ({name}): {e}")

    async def register_process(
        self,
        pid: int,
        process: Any,
        activity_callback: Optional[Callable[[], float]],
        name: str,
    ) -> None:
        """Register a process for monitoring."""
        async with self._lock:
            self._processes[pid] = {
                "process": process,
                "activity_callback": activity_callback,
                "name": name,
                "last_activity": time.time(),
            }
            self._logger.debug(f"Registered process {pid} ({name}) for monitoring")

        # Auto-start watchdog loop if not already active
        if self._watchdog_task is None or self._watchdog_task.done():
            await self.start()

    async def unregister_process(self, pid: int) -> None:
        """Unregister a process from monitoring."""
        async with self._lock:
            if pid in self._processes:
                name = self._processes[pid]["name"]
                del self._processes[pid]
                self._logger.debug(
                    f"Unregistered process {pid} ({name}) from monitoring"
                )

    async def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        async with self._lock:
            if pid in self._processes:
                self._processes[pid]["last_activity"] = time.time()

    async def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered for monitoring."""
        async with self._lock:
            return pid in self._processes

    async def get_stats(self) -> dict:
        """Get statistics about monitored processes."""
        async with self._lock:
            total = len(self._processes)
            running = sum(
                1
                for p in self._processes.values()
                if p["process"].returncode is None
            )

            return {
                "total_processes": total,
                "running_processes": running,
                "finished_processes": total - running,
                "watchdog_active": (
                    self._watchdog_task and not self._watchdog_task.done()
                ),
            }

    async def __aenter__(self):
        """Enter context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        await self.stop()
        return False