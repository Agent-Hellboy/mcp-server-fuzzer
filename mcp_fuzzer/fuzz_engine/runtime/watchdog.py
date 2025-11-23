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
from typing import Any, Callable, TypedDict

from ...config.constants import (
    PROCESS_TERMINATION_TIMEOUT,
    PROCESS_FORCE_KILL_TIMEOUT,
)
from ...exceptions import (
    MCPError,
    ProcessRegistrationError,
    ProcessStopError,
    WatchdogStartError,
)
from .config import WatchdogConfig

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    psutil = None
    HAS_PSUTIL = False


async def wait_for_process_exit(process: Any, timeout: float | None = None) -> Any:
    """Await process.wait() while tolerating synchronous/mocked implementations."""
    wait_result = process.wait()
    if inspect.isawaitable(wait_result):
        if timeout is None:
            return await wait_result
        return await asyncio.wait_for(wait_result, timeout=timeout)
    return wait_result


class WatchdogProcessInfo(TypedDict):
    """Shape for stored watchdog process metadata."""

    process: Any
    activity_callback: Callable[[], float] | None
    name: str
    last_activity: float


class WatchdogProcessTable(dict[int, WatchdogProcessInfo]):
    """Typed mapping for watchdog-managed processes."""

    def snapshot(self) -> dict[int, WatchdogProcessInfo]:
        """Return a shallow copy for safe inspection in tests/monitoring."""
        return dict(self)


class _WatchdogState:
    """Thread-safe storage for watchdog processes and coordination primitives."""

    def __init__(self) -> None:
        self._processes: WatchdogProcessTable = WatchdogProcessTable()
        self._lock: asyncio.Lock | None = None
        self._stop_event: asyncio.Event | None = None

    def get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def get_stop_event(self) -> asyncio.Event:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        return self._stop_event

    async def snapshot(self) -> list[tuple[int, WatchdogProcessInfo]]:
        async with self.get_lock():
            return list(self._processes.items())

    async def remove_many(self, pids: list[int]) -> None:
        if not pids:
            return
        async with self.get_lock():
            for pid in pids:
                self._processes.pop(pid, None)

    async def add(
        self,
        pid: int,
        process: Any,
        activity_callback: Callable[[], float] | None,
        name: str,
    ) -> None:
        async with self.get_lock():
            self._processes[pid] = {
                "process": process,
                "activity_callback": activity_callback,
                "name": name,
                "last_activity": time.time(),
            }

    async def remove(self, pid: int) -> None:
        async with self.get_lock():
            self._processes.pop(pid, None)

    async def update_activity(self, pid: int) -> None:
        async with self.get_lock():
            if pid in self._processes:
                self._processes[pid]["last_activity"] = time.time()

    async def is_registered(self, pid: int) -> bool:
        async with self.get_lock():
            return pid in self._processes

    async def stats(self) -> dict[str, int]:
        async with self.get_lock():
            total = len(self._processes)
            running = sum(
                1 for p in self._processes.values() if p["process"].returncode is None
            )
        return {
            "total_processes": total,
            "running_processes": running,
            "finished_processes": total - running,
        }


class _ProcessKiller:
    """Encapsulate platform-specific process termination."""

    def __init__(self, logger: logging.Logger, config: WatchdogConfig) -> None:
        self._logger = logger
        self._config = config

    async def kill(
        self, pid: int, process: Any, name: str, wait_fn: Callable[..., Any]
    ) -> None:
        try:
            self._logger.info(f"Attempting to kill hanging process {pid} ({name})")

            if sys.platform == "win32":
                process.terminate()
                try:
                    await wait_fn(process, timeout=PROCESS_TERMINATION_TIMEOUT)
                    self._logger.info(
                        f"Gracefully terminated Windows process {pid} ({name})"
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    self._logger.info(f"Force killed Windows process {pid} ({name})")
            else:
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, _signal.SIGTERM)

                    try:
                        await wait_fn(process, timeout=PROCESS_TERMINATION_TIMEOUT)
                        msg = (
                            f"Gracefully terminated Unix process {pid} ({name}) "
                            "with SIGTERM"
                        )
                        self._logger.info(msg)
                    except asyncio.TimeoutError:
                        try:
                            os.killpg(pgid, _signal.SIGKILL)
                            self._logger.info(
                                f"Force killed Unix process {pid} ({name}) with SIGKILL"
                            )
                        except OSError:
                            process.kill()
                            msg = (
                                f"Force killed Unix process {pid} ({name}) "
                                "with process.kill()"
                            )
                            self._logger.info(msg)
                except OSError:
                    process.terminate()
                    try:
                        await wait_fn(process, timeout=PROCESS_TERMINATION_TIMEOUT)
                        msg = (
                            f"Gracefully terminated Unix process {pid} ({name}) "
                            "with process.terminate()"
                        )
                        self._logger.info(msg)
                    except asyncio.TimeoutError:
                        process.kill()
                        msg = (
                            f"Force killed Unix process {pid} ({name}) "
                            "with process.kill()"
                        )
                        self._logger.info(msg)

            try:
                await wait_fn(process, timeout=PROCESS_FORCE_KILL_TIMEOUT)
            except asyncio.TimeoutError:
                self._logger.warning(
                    f"Process {pid} ({name}) did not exit after kill within "
                    f"{PROCESS_FORCE_KILL_TIMEOUT}s"
                )

            self._logger.info(f"Successfully killed hanging process {pid} ({name})")

        except Exception as e:
            self._logger.error(f"Failed to kill process {pid} ({name}): {e}")
            raise ProcessStopError(
                f"Failed to terminate process {pid} ({name})",
                context={"pid": pid, "name": name},
            ) from e


class ProcessWatchdog:
    """Fully asynchronous process monitoring system."""

    def __init__(self, config: WatchdogConfig | None = None):
        """Initialize the process watchdog."""
        self.config = config or WatchdogConfig()
        self._store = _WatchdogState()
        # Backwards-compatible aliases for tests/introspection
        self._lock = self._store.get_lock()
        self._stop_event = self._store.get_stop_event()
        self._processes = self._store._processes
        self._logger = logging.getLogger(__name__)
        self._watchdog_task: asyncio.Task | None = None
        self._terminator = _ProcessKiller(self._logger, self.config)

    @property
    def processes(self) -> WatchdogProcessTable:
        """Public access to the typed process table (read/update with care)."""
        return self._store._processes

    async def get_process_snapshot(self, pid: int) -> WatchdogProcessInfo | None:
        """Test-friendly accessor for stored process info."""
        async with self._store.get_lock():
            return self._store._processes.get(pid)

    async def list_registered_pids(self) -> list[int]:
        """List registered process IDs."""
        async with self._store.get_lock():
            return list(self._store._processes.keys())

    def _get_lock(self) -> asyncio.Lock:
        """Compat: return the shared process store lock."""
        return self._store.get_lock()

    def _get_stop_event(self) -> asyncio.Event:
        """Compat: return the shared stop event."""
        return self._store.get_stop_event()

    async def _wait_for_process_exit(
        self, process: Any, timeout: float | None = None
    ) -> Any:
        """Await process.wait() while tolerating synchronous/mocked implementations."""
        wait_result = process.wait()
        if inspect.isawaitable(wait_result):
            if timeout is None:
                return await wait_result
            return await asyncio.wait_for(wait_result, timeout=timeout)
        return wait_result

    async def wait_for_process_exit(
        self, process: Any, timeout: float | None = None
    ) -> Any:
        """Public wrapper for awaiting process exit."""
        return await self._wait_for_process_exit(process, timeout)

    async def start(self) -> None:
        """Start the watchdog monitoring."""
        if self._watchdog_task is None or self._watchdog_task.done():
            try:
                self._store.get_stop_event().clear()
                self._watchdog_task = asyncio.create_task(self._watchdog_loop())
                self._logger.info("Process watchdog started")
            except MCPError:
                raise
            except Exception as e:
                self._logger.error(f"Failed to start process watchdog: {e}")
                raise WatchdogStartError(
                    "Failed to start process watchdog",
                    context={
                        "check_interval": self.config.check_interval,
                        "process_timeout": self.config.process_timeout,
                    },
                ) from e

    async def stop(self) -> None:
        """Stop the watchdog monitoring."""
        if self._watchdog_task and not self._watchdog_task.done():
            self._store.get_stop_event().set()
            # Don't wait for the task to complete - just cancel it
            self._watchdog_task.cancel()
            self._watchdog_task = None
            self._logger.info("Process watchdog stopped")

    async def _watchdog_loop(self) -> None:
        """Main watchdog monitoring loop."""
        while not self._store.get_stop_event().is_set():
            try:
                await self._scan_processes()

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

    async def _scan_processes(self) -> None:
        """Check all registered processes for hanging behavior."""
        current_time = time.time()
        processes_to_remove = []

        processes_snapshot = await self._store.snapshot()

        for pid, process_info in processes_snapshot:
            try:
                process = process_info["process"]
                name = process_info["name"]

                # Check if process is still running
                if process.returncode is None:
                    # Process is running, check activity
                    last_activity = await self._resolve_last_activity(process_info)
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

        if processes_to_remove:
            await self._store.remove_many(processes_to_remove)

    async def _resolve_last_activity(self, process_info: WatchdogProcessInfo) -> float:
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
        await self._terminator.kill(pid, process, name, self._wait_for_process_exit)

    async def register_process(
        self,
        pid: int,
        process: Any,
        activity_callback: Callable[[], float] | None,
        name: str,
    ) -> None:
        """Register a process for monitoring."""
        try:
            await self._store.add(pid, process, activity_callback, name)
            self._logger.debug(f"Registered process {pid} ({name}) for monitoring")

            # Auto-start watchdog loop if not already active
            if self._watchdog_task is None or self._watchdog_task.done():
                await self.start()
        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to register process {pid} ({name}): {e}")
            raise ProcessRegistrationError(
                f"Failed to register process {pid} ({name})",
                context={"pid": pid, "name": name},
            ) from e

    async def unregister_process(self, pid: int) -> None:
        """Unregister a process from monitoring."""
        try:
            async with self._store.get_lock():
                if pid in self._store._processes:
                    name = self._store._processes[pid]["name"]
                    del self._store._processes[pid]
                    self._logger.debug(
                        f"Unregistered process {pid} ({name}) from monitoring"
                    )
        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to unregister process {pid}: {e}")
            raise ProcessRegistrationError(
                f"Failed to unregister process {pid}",
                context={"pid": pid},
            ) from e

    async def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        await self._store.update_activity(pid)

    async def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered for monitoring."""
        return await self._store.is_registered(pid)

    async def get_stats(self) -> dict:
        """Get statistics about monitored processes."""
        stats = await self._store.stats()
        stats["watchdog_active"] = (
            self._watchdog_task and not self._watchdog_task.done()
        )
        return stats

    async def get_performance_metrics(self) -> dict[str, Any]:
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
            async with self._store.get_lock():
                total_processes = len(self._store._processes)
                running_processes = sum(
                    1 for p in self._store._processes.values()
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
            async with self._store.get_lock():
                process_count = len(self._store._processes)

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
