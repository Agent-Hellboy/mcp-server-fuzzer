#!/usr/bin/env python3
"""
Process Watchdog for MCP Fuzzer Runtime (registry-backed, signal-driven).

This implementation monitors processes stored in ProcessRegistry, detects hangs,
and delegates termination through a pluggable TerminationStrategy (default:
SignalDispatcher). It avoids maintaining a parallel process table; only
per-process activity timestamps are tracked locally for hang detection.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import signal as _signal
import sys
import time
from typing import Any, Awaitable, Callable, Protocol

# Import constants directly from config (constants are values, not behavior)
# Behavior (functions/classes) should go through client mediator
from ...config.core.constants import (
    PROCESS_FORCE_KILL_TIMEOUT,
    PROCESS_TERMINATION_TIMEOUT,
)
from ...exceptions import MCPError, ProcessStopError, WatchdogStartError
from .config import WatchdogConfig
from .registry import ProcessRecord, ProcessRegistry
from .signals import SignalDispatcher

# Type aliases
Clock = Callable[[], float]
ActivityCallback = Callable[[], float | bool | Awaitable[float | bool]]


async def wait_for_process_exit(process: Any, timeout: float | None = None) -> Any:
    """Await process.wait() while tolerating synchronous/mocked implementations."""
    wait_result = process.wait()
    if inspect.isawaitable(wait_result):
        if timeout is None:
            return await wait_result
        return await asyncio.wait_for(wait_result, timeout=timeout)
    return wait_result


class TerminationStrategy(Protocol):
    """Pluggable process termination strategy."""

    async def terminate(
        self, pid: int, process_info: ProcessRecord, hang_duration: float
    ) -> bool:
        """Attempt to terminate a hung process. Return True if signals were sent."""


class SignalTerminationStrategy:
    """Termination strategy that uses SignalDispatcher for timeout/force signals."""

    def __init__(
        self,
        dispatcher: SignalDispatcher,
        logger: logging.Logger,
        graceful_timeout: float = PROCESS_TERMINATION_TIMEOUT,
        force_timeout: float = PROCESS_FORCE_KILL_TIMEOUT,
        wait_fn: Callable[[Any, float | None], Awaitable[Any]] = wait_for_process_exit,
    ) -> None:
        self._dispatcher = dispatcher
        self._logger = logger
        self._graceful_timeout = graceful_timeout
        self._force_timeout = force_timeout
        self._wait_fn = wait_fn

    async def _await_exit(
        self,
        process: Any,
        pid: int,
        name: str,
        timeout: float,
        stage: str,
    ) -> bool:
        try:
            await self._wait_fn(process, timeout=timeout)
            return True
        except asyncio.TimeoutError:
            self._logger.warning(
                "Process %s (%s) did not exit after %s within %.1fs",
                pid,
                name,
                stage,
                timeout,
            )
            return False

    async def terminate(
        self, pid: int, process_info: ProcessRecord, hang_duration: float
    ) -> bool:
        process = process_info["process"]
        name = process_info["config"].name

        try:
            await self._dispatcher.send("timeout", pid, process_info)
            if await self._await_exit(
                process, pid, name, self._graceful_timeout, "graceful termination"
            ):
                self._logger.info(
                    "Gracefully terminated hung process %s (%s) after %.1fs",
                    pid,
                    name,
                    hang_duration,
                )
                return True

            self._logger.info("Escalating to force kill for process %s (%s)", pid, name)
            await self._dispatcher.send("force", pid, process_info)

            if await self._await_exit(
                process, pid, name, self._force_timeout, "force kill"
            ):
                self._logger.info(
                    "Forcefully terminated hung process %s (%s)", pid, name
                )
                return True
            return False
        except Exception as exc:  # pragma: no cover - safety net
            self._logger.error(
                "Termination strategy failed for process %s (%s): %s",
                pid,
                name,
                exc,
            )
            return False


class BestEffortTerminationStrategy:
    """Fallback termination strategy that attempts OS-level kills directly."""

    def __init__(
        self,
        logger: logging.Logger,
        wait_fn: Callable[[Any, float | None], Awaitable[Any]] = wait_for_process_exit,
    ) -> None:
        self._logger = logger
        self._wait_fn = wait_fn

    async def _await_exit(
        self,
        process: Any,
        pid: int,
        name: str,
        timeout: float,
        stage: str,
    ) -> bool:
        try:
            await self._wait_fn(process, timeout=timeout)
            return True
        except asyncio.TimeoutError:
            self._logger.warning(
                "Process %s (%s) did not exit after %s within %.1fs",
                pid,
                name,
                stage,
                timeout,
            )
            return False

    async def terminate(
        self, pid: int, process_info: ProcessRecord, hang_duration: float
    ) -> bool:
        process = process_info["process"]
        name = process_info["config"].name

        try:
            if sys.platform == "win32":
                process.terminate()
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_TERMINATION_TIMEOUT,
                    "termination",
                ):
                    self._logger.info(
                        "Gracefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True
                process.kill()
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_FORCE_KILL_TIMEOUT,
                    "force kill",
                ):
                    self._logger.info(
                        "Forcefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True

            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, _signal.SIGTERM)
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_TERMINATION_TIMEOUT,
                    "termination",
                ):
                    self._logger.info(
                        "Gracefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True
                os.killpg(pgid, _signal.SIGKILL)
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_FORCE_KILL_TIMEOUT,
                    "force kill",
                ):
                    self._logger.info(
                        "Forcefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True
            except OSError:
                process.terminate()
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_TERMINATION_TIMEOUT,
                    "termination",
                ):
                    self._logger.info(
                        "Gracefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True
                process.kill()
                if await self._await_exit(
                    process,
                    pid,
                    name,
                    PROCESS_FORCE_KILL_TIMEOUT,
                    "force kill",
                ):
                    self._logger.info(
                        "Forcefully terminated hanging process %s (%s)",
                        pid,
                        name,
                    )
                    return True
        except Exception as exc:
            self._logger.error(
                "Best-effort kill failed for process %s (%s): %s", pid, name, exc
            )
            raise ProcessStopError(
                f"Failed to terminate process {pid} ({name})",
                context={"pid": pid, "name": name},
            ) from exc
        return False


async def _normalize_activity(
    callback: ActivityCallback | None,
    last_activity: float,
    now: float,
    logger: logging.Logger,
) -> float:
    """Resolve an activity timestamp from a callback or fall back to last value."""
    if not callback:
        return last_activity

    try:
        result = callback()
        if inspect.isawaitable(result):
            result = await result
    except Exception:
        logger.debug("Activity callback failed; using stored timestamp", exc_info=True)
        return last_activity

    try:
        if isinstance(result, bool):
            return now if result else last_activity
        timestamp = float(result)
        if timestamp < 0 or timestamp > now + 1:
            logger.debug("Activity callback returned invalid timestamp: %s", timestamp)
            return last_activity
        return timestamp
    except Exception:
        logger.debug(
            "Activity callback returned non-numeric/invalid value; "
            "using stored timestamp"
        )
        return last_activity


class ProcessWatchdog:
    """Registry-backed process watchdog with pluggable termination strategy."""

    def __init__(
        self,
        registry: ProcessRegistry,
        signal_dispatcher: SignalDispatcher | None,
        config: WatchdogConfig | None = None,
        *,
        termination_strategy: TerminationStrategy | None = None,
        clock: Clock | None = None,
        logger: logging.Logger | None = None,
        metrics_sampler: Callable[[], dict[str, Any]] | None = None,
        on_hang: Callable[[int, ProcessRecord, float], None] | None = None,
    ) -> None:
        self.config = config or WatchdogConfig()
        self.registry = registry
        self._logger = logger or logging.getLogger(__name__)
        self._clock = clock or time.time
        self._stop_event: asyncio.Event | None = None
        self._task: asyncio.Task | None = None
        self._last_activity: dict[int, float] = {}
        self._last_scan_at: float | None = None
        self._last_error: str | None = None
        self._metrics_sampler = metrics_sampler
        self._on_hang = on_hang

        if termination_strategy:
            self._terminator = termination_strategy
        elif signal_dispatcher:
            self._terminator = SignalTerminationStrategy(
                signal_dispatcher, self._logger
            )
        else:
            self._terminator = BestEffortTerminationStrategy(self._logger)

    def _get_stop_event(self) -> asyncio.Event:
        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        return self._stop_event

    async def start(self) -> None:
        """Explicitly start the monitoring loop."""
        if self._task and not self._task.done():
            return
        try:
            self._get_stop_event().clear()
            self._task = asyncio.create_task(self._run_loop())
            self._logger.info("Process watchdog started")
        except MCPError:
            raise
        except Exception as exc:
            raise WatchdogStartError(
                "Failed to start process watchdog",
                context={
                    "check_interval": self.config.check_interval,
                    "process_timeout": self.config.process_timeout,
                },
            ) from exc

    async def stop(self) -> None:
        """Stop the monitoring loop, awaiting cancellation."""
        if self._task and not self._task.done():
            self._get_stop_event().set()
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self._logger.info("Process watchdog stopped")

    async def update_activity(self, pid: int) -> None:
        """Record recent activity for a process."""
        self._last_activity[pid] = self._clock()

    async def scan_once(self, processes: dict[int, ProcessRecord]) -> dict[str, Any]:
        """Run a single hang detection pass using provided registry snapshot."""
        now = self._clock()
        self._last_scan_at = now
        removed: list[int] = []
        hung: list[int] = []
        killed: list[int] = []

        # Drop metadata for pids no longer present
        missing = set(self._last_activity.keys()) - set(processes.keys())
        for pid in missing:
            self._last_activity.pop(pid, None)

        for pid, process_info in processes.items():
            process = process_info["process"]
            config = process_info["config"]
            name = config.name

            # Initialize activity baseline
            last_activity = self._last_activity.get(
                pid, process_info.get("started_at", now)
            )

            # Finished? mark for removal
            if getattr(process, "returncode", None) is not None:
                removed.append(pid)
                self._last_activity.pop(pid, None)
                continue

            # Resolve activity
            callback = getattr(config, "activity_callback", None)
            latest_activity = await _normalize_activity(
                callback, last_activity, now, self._logger
            )
            self._last_activity[pid] = latest_activity

            time_since = now - latest_activity
            hang_threshold = self.config.process_timeout + self.config.extra_buffer

            if time_since > hang_threshold:
                hung.append(pid)
                if self._on_hang:
                    try:
                        self._on_hang(pid, process_info, time_since)
                    except Exception:
                        self._logger.debug("on_hang handler failed", exc_info=True)

                should_kill = self.config.auto_kill or (
                    time_since > self.config.max_hang_time
                )
                if should_kill:
                    success = await self._terminator.terminate(
                        pid, process_info, time_since
                    )
                    if success:
                        killed.append(pid)
                        self._last_activity.pop(pid, None)
                        try:
                            await self.registry.update_status(pid, "stopped")
                        except Exception:
                            pass
                        removed.append(pid)
            elif time_since > self.config.process_timeout:
                self._logger.debug(
                    "Process %s (%s) slow: %.1fs since activity", pid, name, time_since
                )

        # Remove finished/hung processes from registry to avoid churn/memory growth
        for pid in removed:
            try:
                await self.registry.unregister(pid)
            except Exception:
                self._logger.debug("Failed to unregister pid %s from registry", pid)

        return {
            "hung": hung,
            "killed": killed,
            "removed": removed,
            "timestamp": now,
        }

    async def get_stats(self) -> dict[str, Any]:
        """Return lightweight stats for observability."""
        snapshot = await self.registry.snapshot()
        total = len(snapshot)
        running = sum(
            1
            for record in snapshot.values()
            if getattr(record["process"], "returncode", None) is None
        )
        stats = {
            "total_processes": total,
            "running_processes": running,
            "finished_processes": total - running,
            "watchdog_active": bool(self._task and not self._task.done()),
            "last_scan_at": self._last_scan_at,
            "last_error": self._last_error,
        }
        if self._metrics_sampler:
            try:
                stats["system_metrics"] = self._metrics_sampler()
            except Exception:
                self._logger.debug("Metrics sampler failed", exc_info=True)
        return stats

    async def _run_loop(self) -> None:
        """Main monitoring loop with simple error backoff."""
        interval = self.config.check_interval
        while not self._get_stop_event().is_set():
            try:
                snapshot = await self.registry.snapshot()
                await self.scan_once(snapshot)
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_error = str(exc)
                self._logger.error("Error in watchdog loop: %s", exc)
                await asyncio.sleep(min(interval, 1.0))

    async def __aenter__(self) -> "ProcessWatchdog":
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        await self.stop()
        return False
