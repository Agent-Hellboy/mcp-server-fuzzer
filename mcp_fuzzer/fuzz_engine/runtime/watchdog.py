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

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False


@dataclass
class WatchdogConfig:
    """Configuration for the process watchdog."""

    check_interval: float = 1.0  # How often to check processes (seconds)
    process_timeout: float = 30.0  # Time before process is considered hanging (seconds)
    extra_buffer: float = 5.0  # Extra time before auto-kill (seconds)
    max_hang_time: float = 60.0  # Maximum time before force kill (seconds)
    auto_kill: bool = True  # Whether to automatically kill hanging processes

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "WatchdogConfig":
        """Create WatchdogConfig from configuration dictionary."""
        return cls(
            check_interval=config.get("watchdog_check_interval", 1.0),
            process_timeout=config.get("watchdog_process_timeout", 30.0),
            extra_buffer=config.get("watchdog_extra_buffer", 5.0),
            max_hang_time=config.get("watchdog_max_hang_time", 60.0),
            auto_kill=config.get("auto_kill", True),
        )


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

                # Adaptive sleep interval based on system load
                sleep_interval = await self._calculate_adaptive_interval()
                await asyncio.sleep(sleep_interval)
            except asyncio.CancelledError:
                # Handle cancellation gracefully
                self._logger.debug("Watchdog loop cancelled")
                break
            except Exception as e:
                self._logger.error(f"Error in watchdog loop: {e}")
                # Use a shorter delay on error to avoid flooding logs
                await asyncio.sleep(min(self.config.check_interval, 5.0))

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
                        last_activity = await self._get_last_activity(process_info)
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

    async def _get_last_activity(self, process_info: dict) -> float:
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
                    exc_info=True,
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
                1 for p in self._processes.values() if p["process"].returncode is None
            )

            return {
                "total_processes": total,
                "running_processes": running,
                "finished_processes": total - running,
                "watchdog_active": (
                    self._watchdog_task and not self._watchdog_task.done()
                ),
            }

    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for monitoring and optimization."""
        try:
            system_metrics = {}
            if HAS_PSUTIL and psutil:
                # System metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                system_metrics = {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "memory_used_gb": memory.used / (1024**3),
                    "disk_percent": disk.percent,
                }
            else:
                system_metrics = {"psutil_not_available": True}

            # Process metrics
            async with self._lock:
                total_processes = len(self._processes)
                running_processes = sum(
                    1 for p in self._processes.values()
                    if p["process"].returncode is None
                )

            return {
                "system": system_metrics,
                "processes": {
                    "total": total_processes,
                    "running": running_processes,
                    "finished": total_processes - running_processes,
                },
                "watchdog": {
                    "active": self._watchdog_task and not self._watchdog_task.done(),
                    "check_interval": self.config.check_interval,
                    "process_timeout": self.config.process_timeout,
                },
                "timestamp": time.time(),
            }
        except Exception as e:
            self._logger.warning(f"Failed to collect performance metrics: {e}")
            return {"error": str(e), "timestamp": time.time()}

    async def _calculate_adaptive_interval(self) -> float:
        """Calculate adaptive check interval based on system load and process count."""
        try:
            async with self._lock:
                process_count = len(self._processes)

            # Base interval from config
            base_interval = self.config.check_interval

            # Only apply system-based adjustments if psutil is available
            if HAS_PSUTIL and psutil:
                # Get current system metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()

                # Adjust based on CPU usage
                if cpu_percent > 80:
                    # High CPU: increase interval to reduce load
                    cpu_multiplier = 2.0
                elif cpu_percent > 60:
                    cpu_multiplier = 1.5
                elif cpu_percent < 20:
                    # Low CPU: can check more frequently
                    cpu_multiplier = 0.8
                else:
                    cpu_multiplier = 1.0

                # Adjust based on memory usage
                if memory.percent > 85:
                    # High memory: increase interval
                    memory_multiplier = 1.8
                elif memory.percent > 70:
                    memory_multiplier = 1.3
                else:
                    memory_multiplier = 1.0

                # Log significant changes
                adaptive_interval = base_interval * cpu_multiplier * memory_multiplier
                if abs(adaptive_interval - base_interval) > 0.5:
                    self._logger.debug(
                        f"Adaptive interval: {adaptive_interval:.1f}s "
                        f"(CPU: {cpu_percent:.1f}%, Mem: {memory.percent:.1f}%)"
                    )
            else:
                # Fallback to process-count-based adjustment only
                adaptive_interval = base_interval

            # Adjust based on process count (always available)
            if process_count > 20:
                # Many processes: increase interval
                adaptive_interval *= 1.5
            elif process_count > 10:
                adaptive_interval *= 1.2
            elif process_count < 3:
                # Few processes: can check less frequently
                adaptive_interval *= 0.9

            # Clamp to reasonable bounds
            adaptive_interval = max(0.5, min(adaptive_interval, 10.0))

            return adaptive_interval

        except Exception as e:
            self._logger.debug(f"Failed to calculate adaptive interval: {e}")
            return self.config.check_interval

    async def __aenter__(self):
        """Enter context manager."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager."""
        await self.stop()
        return False
