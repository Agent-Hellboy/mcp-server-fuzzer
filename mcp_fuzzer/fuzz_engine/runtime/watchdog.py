#!/usr/bin/env python3
"""
Process Watchdog for MCP Fuzzer Runtime

This module provides process monitoring functionality with non-blocking
async operations.
"""

import asyncio
import logging
import os
import signal as _signal
import sys
import threading
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
    """Monitors processes for hanging behavior with non-blocking async operations."""

    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the process watchdog."""
        self.config = config or WatchdogConfig()
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()  # Use threading.Lock for sync methods
        self._async_lock = asyncio.Lock()  # Use asyncio.Lock for async methods
        self._logger = logging.getLogger(__name__)
        self._stop_event = asyncio.Event()
        self._watchdog_task: Optional[asyncio.Task] = None
        self._loop = None  # Initialize lazily when needed

    def _get_loop(self):
        """Get the event loop, initializing it if needed."""
        if self._loop is None:
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                # Create a new event loop if none exists
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def start(self) -> None:
        """Start the watchdog monitoring."""
        if self._watchdog_task is None or self._watchdog_task.done():
            self._stop_event.clear()
            loop = self._get_loop()
            self._watchdog_task = loop.create_task(self._watchdog_loop())
            self._logger.info("Process watchdog started")

    def stop(self) -> None:
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

        async with self._async_lock:
            for pid, process_info in self._processes.items():
                try:
                    process = process_info["process"]
                    name = process_info["name"]

                    # Check if process is still running
                    if hasattr(process, "returncode") and process.returncode is None:
                        # Process is running, check activity
                        last_activity = self._get_last_activity(
                            process_info, current_time
                        )
                        time_since_activity = current_time - last_activity

                        if (
                            time_since_activity
                            > self.config.process_timeout + self.config.extra_buffer
                        ):
                            # Process is hanging
                            threshold = (
                                self.config.process_timeout + self.config.extra_buffer
                            )
                            self._logger.warning(
                                (
                                    f"Process {pid} ({name}) hanging for "
                                    f"{time_since_activity:.1f}s, "
                                    f"threshold: {threshold:.1f}s"
                                )
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
                                (
                                    f"Process {pid} ({name}) slow: "
                                    f"{time_since_activity:.1f}s since last activity"
                                )
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

    def _get_last_activity(self, process_info: dict, current_time: float) -> float:
        """Get the last activity timestamp for a process."""
        # Try to get activity from callback first
        if process_info["activity_callback"]:
            try:
                return process_info["activity_callback"]()
            except Exception:
                pass

        # Fall back to stored timestamp
        return process_info["last_activity"]

    async def _kill_process(self, pid: int, process: Any, name: str) -> None:
        """Kill a hanging process with graceful shutdown first."""
        try:
            self._logger.info(f"Attempting to kill hanging process {pid} ({name})")

            # Run the killing logic in a thread pool to avoid blocking
            await self._get_loop().run_in_executor(
                None, self._kill_process_sync, pid, process, name
            )

            self._logger.info(f"Successfully killed hanging process {pid} ({name})")

        except Exception as e:
            self._logger.error(f"Failed to kill process {pid} ({name}): {e}")

    def _kill_process_sync(self, pid: int, process: Any, name: str) -> None:
        """Synchronous process killing (runs in thread pool)."""
        if sys.platform == "win32":
            # Windows: try graceful termination first
            try:
                process.terminate()
                # Give it a moment to terminate gracefully (non-blocking)
                time.sleep(0.1)  # Very short sleep to prevent hanging
                if hasattr(process, "returncode") and process.returncode is None:
                    process.kill()
                    self._logger.info(f"Force killed Windows process {pid} ({name})")
                else:
                    self._logger.info(
                        "Gracefully terminated Windows process %s (%s)", pid, name
                    )
            except (AttributeError, ValueError):
                process.kill()
                self._logger.info(f"Force killed Windows process {pid} ({name})")
        else:
            # Unix-like systems: try SIGTERM first, then SIGKILL
            try:
                # Send SIGTERM for graceful shutdown
                pgid = os.getpgid(pid)
                os.killpg(pgid, _signal.SIGTERM)

                # Wait a bit for graceful shutdown (non-blocking)
                time.sleep(0.2)  # Very short sleep to prevent hanging

                # Check if process is still running
                if hasattr(process, "returncode") and process.returncode is None:
                    # Process still running, force kill with SIGKILL
                    try:
                        os.killpg(pgid, _signal.SIGKILL)
                        self._logger.info(
                            f"Force killed Unix process {pid} ({name}) with SIGKILL"
                        )
                    except OSError:
                        # Fallback to process.kill()
                        process.kill()
                        self._logger.info(
                            (
                                f"Force killed Unix process {pid} ({name}) "
                                "with process.kill()"
                            )
                        )
                else:
                    self._logger.info(
                        (
                            f"Gracefully terminated Unix process {pid} ({name}) "
                            "with SIGTERM"
                        )
                    )

            except OSError:
                # Process group not accessible, try direct process termination
                try:
                    process.terminate()
                    time.sleep(0.1)  # Very short sleep to prevent hanging
                    if hasattr(process, "returncode") and process.returncode is None:
                        process.kill()
                        self._logger.info(
                            (
                                f"Force killed Unix process {pid} ({name}) "
                                "with process.kill()"
                            )
                        )
                    else:
                        self._logger.info(
                            (
                                f"Gracefully terminated Unix process {pid} ({name}) "
                                "with process.terminate()"
                            )
                        )
                except Exception:
                    # Last resort: force kill
                    process.kill()
                    self._logger.info(
                        "Force killed Unix process %s (%s) as last resort", pid, name
                    )

    def register_process(
        self,
        pid: int,
        process: Any,
        activity_callback: Optional[Callable[[], float]],
        name: str,
    ) -> None:
        """Register a process for monitoring."""
        with self._lock:
            self._processes[pid] = {
                "process": process,
                "activity_callback": activity_callback,
                "name": name,
                "last_activity": time.time(),
            }
            self._logger.debug(f"Registered process {pid} ({name}) for monitoring")
        # Auto-start watchdog loop if not already active
        try:
            if self._watchdog_task is None or self._watchdog_task.done():
                self.start()
        except Exception as e:
            self._logger.warning(
                "Failed to auto-start watchdog after registering process %s (%s): %s",
                pid,
                name,
                e,
            )

    def unregister_process(self, pid: int) -> None:
        """Unregister a process from monitoring."""
        with self._lock:
            if pid in self._processes:
                name = self._processes[pid]["name"]
                del self._processes[pid]
                self._logger.debug(
                    "Unregistered process %s (%s) from monitoring", pid, name
                )

    def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        with self._lock:
            if pid in self._processes:
                self._processes[pid]["last_activity"] = time.time()

    def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered for monitoring."""
        with self._lock:
            return pid in self._processes

    def get_stats(self) -> dict:
        """Get statistics about monitored processes."""
        with self._lock:
            total = len(self._processes)
            running = sum(
                1
                for p in self._processes.values()
                if hasattr(p["process"], "returncode")
                and p["process"].returncode is None
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
        self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        self.stop()
        return False
