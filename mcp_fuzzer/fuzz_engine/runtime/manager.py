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
from typing import Any, Callable, Protocol

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


class ProcessConfigBuilder:
    """Builder to compose ProcessConfig instances with clear, chainable options."""

    def __init__(self) -> None:
        self._command: list[str] = []
        self._cwd: str | Path | None = None
        self._env: dict[str, str] | None = None
        self._timeout: float = 30.0
        self._auto_kill: bool = True
        self._name: str = "unknown"
        self._activity_callback: Callable[[], float] | None = None

    def with_command(self, command: list[str]) -> "ProcessConfigBuilder":
        self._command = command
        return self

    def with_cwd(self, cwd: str | Path | None) -> "ProcessConfigBuilder":
        self._cwd = cwd
        return self

    def with_env(self, env: dict[str, str] | None) -> "ProcessConfigBuilder":
        self._env = env
        return self

    def with_timeout(self, timeout: float) -> "ProcessConfigBuilder":
        self._timeout = timeout
        return self

    def with_auto_kill(self, auto_kill: bool) -> "ProcessConfigBuilder":
        self._auto_kill = auto_kill
        return self

    def with_name(self, name: str) -> "ProcessConfigBuilder":
        self._name = name
        return self

    def with_activity_callback(
        self, callback: Callable[[], float] | None
    ) -> "ProcessConfigBuilder":
        self._activity_callback = callback
        return self

    def build(self) -> ProcessConfig:
        return ProcessConfig(
            command=self._command,
            cwd=self._cwd,
            env=self._env,
            timeout=self._timeout,
            auto_kill=self._auto_kill,
            name=self._name,
            activity_callback=self._activity_callback,
        )


def _normalize_returncode(value: Any) -> int | None:
    """Return an integer returncode or None, ignore mock objects."""
    if value is None or isinstance(value, int):
        return value
    return None


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
    process: asyncio.subprocess.Process, timeout: float | None = None
) -> Any:
    """Await process.wait() while tolerating mocked/synchronous implementations."""
    wait_result = process.wait()
    if inspect.isawaitable(wait_result):
        if timeout is None:
            return await wait_result
        return await asyncio.wait_for(wait_result, timeout=timeout)
    return wait_result


class ProcessRegistry:
    """SINGLE responsibility: Track running processes"""

    def __init__(self) -> None:
        self._processes: dict[int, dict[str, Any]] = {}
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def register(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        config: ProcessConfig,
        started_at: float | None = None,
        status: str = "running",
    ) -> None:
        async with self._get_lock():
            self._processes[pid] = {
                "process": process,
                "config": config,
                "started_at": started_at or time.time(),
                "status": status,
            }

    async def unregister(self, pid: int) -> None:
        async with self._get_lock():
            self._processes.pop(pid, None)

    async def get_process(self, pid: int) -> dict[str, Any] | None:
        async with self._get_lock():
            return self._processes.get(pid)

    async def list_pids(self) -> list[int]:
        async with self._get_lock():
            return list(self._processes.keys())

    async def update_status(self, pid: int, status: str) -> None:
        async with self._get_lock():
            if pid in self._processes:
                self._processes[pid]["status"] = status

    async def clear(self) -> None:
        async with self._get_lock():
            self._processes.clear()


class ProcessSignalStrategy(Protocol):
    """Strategy interface for sending signals to processes."""

    async def send(
        self, pid: int, process_info: dict[str, Any] | None = None
    ) -> bool: ...


class _BaseSignalStrategy:
    """Shared helpers for concrete signal strategies."""

    def __init__(self, registry: ProcessRegistry, logger: logging.Logger) -> None:
        self._registry = registry
        self._logger = logger

    async def _resolve_process(
        self, pid: int, process_info: dict[str, Any] | None = None
    ) -> tuple[asyncio.subprocess.Process, str] | tuple[None, None]:
        info = process_info or await self._registry.get_process(pid)
        if not info:
            return None, None
        process = info["process"]
        name = info["config"].name
        return process, name


class TermSignalStrategy(_BaseSignalStrategy):
    async def send(
        self, pid: int, process_info: dict[str, Any] | None = None
    ) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if not process:
            return False
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
        return True


class KillSignalStrategy(_BaseSignalStrategy):
    async def send(
        self, pid: int, process_info: dict[str, Any] | None = None
    ) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if not process:
            return False
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
        return True


class InterruptSignalStrategy(_BaseSignalStrategy):
    async def send(
        self, pid: int, process_info: dict[str, Any] | None = None
    ) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if not process:
            return False
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
        return True


class ProcessSignalHandler:
    """SINGLE responsibility: Send signals to processes using pluggable strategies."""

    def __init__(self, registry: ProcessRegistry, logger: logging.Logger) -> None:
        self._registry = registry
        self._logger = logger
        self._signal_map: dict[str, ProcessSignalStrategy] = {
            "timeout": TermSignalStrategy(registry, logger),
            "force": KillSignalStrategy(registry, logger),
            "interrupt": InterruptSignalStrategy(registry, logger),
        }

    async def send(
        self, signal_type: str, pid: int, process_info: dict[str, Any] | None = None
    ) -> bool:
        handler = self._signal_map.get(signal_type)
        if handler is None:
            self._logger.warning(f"Unknown signal type: {signal_type}")
            return False
        return await handler.send(pid, process_info)


class ProcessLifecycleManager:
    """SINGLE responsibility: Start and stop processes"""

    def __init__(
        self,
        watchdog: ProcessWatchdog,
        registry: ProcessRegistry,
        signal_handler: ProcessSignalHandler,
        logger: logging.Logger,
    ) -> None:
        self.watchdog = watchdog
        self.registry = registry
        self.signal_handler = signal_handler
        self._logger = logger

    async def start(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        """Start a new process asynchronously."""
        cwd = str(config.cwd) if isinstance(config.cwd, Path) else config.cwd
        env = (
            {**os.environ, **(config.env or {})}
            if config.env is not None
            else os.environ.copy()
        )

        try:
            await self.watchdog.start()
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

            returncode = _normalize_returncode(process.returncode)
            if returncode is not None:
                stderr = await process.stderr.read()
                stdout = await process.stdout.read()
                error_output = (
                    _format_output(stderr) or _format_output(stdout) or "No output"
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
                        "stderr": _format_output(stderr),
                        "stdout": _format_output(stdout),
                    },
                )

            await self.watchdog.register_process(
                process.pid, process, config.activity_callback, config.name
            )
            await self.registry.register(process.pid, process, config)
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

    async def stop(self, pid: int, force: bool = False) -> bool:
        """Stop a running process asynchronously."""
        process_info = await self.registry.get_process(pid)
        if not process_info:
            return False

        process = process_info["process"]
        name = process_info["config"].name
        try:
            returncode = _normalize_returncode(process.returncode)
            if returncode is not None:
                self._logger.debug(
                    "Process %s (%s) already exited with code %s",
                    pid,
                    name,
                    returncode,
                )
                await self.registry.update_status(pid, "stopped")
                await self.watchdog.unregister_process(pid)
                return True

            if force:
                await self._force_kill_process(pid, process_info)
            else:
                await self._graceful_terminate_process(pid, process_info)

            await self.registry.update_status(pid, "stopped")
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
        self, pid: int, process_info: dict[str, Any]
    ) -> None:
        """Force kill a process."""
        process = process_info["process"]
        name = process_info["config"].name
        await self.signal_handler.send("force", pid, process_info)
        try:
            await _wait_for_process_exit(process, timeout=1.0)
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Process {pid} ({name}) didn't respond to kill signal"
            )

    async def _graceful_terminate_process(
        self, pid: int, process_info: dict[str, Any]
    ) -> None:
        """Gracefully terminate a process."""
        process = process_info["process"]
        name = process_info["config"].name
        await self.signal_handler.send("timeout", pid, process_info)
        try:
            await _wait_for_process_exit(process, timeout=2.0)
            self._logger.info(f"Gracefully stopped process {pid} ({name})")
        except asyncio.TimeoutError:
            self._logger.info(f"Escalating to SIGKILL for process {pid} ({name})")
            await self._force_kill_process(pid, process_info)

    async def stop_all(self, force: bool = False) -> None:
        """Stop all running processes asynchronously."""
        pids = await self.registry.list_pids()
        tasks = [self.stop(pid, force=force) for pid in pids]
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


class ProcessMonitor:
    """SINGLE responsibility: Monitor process health"""

    def __init__(
        self,
        registry: ProcessRegistry,
        watchdog: ProcessWatchdog,
        logger: logging.Logger,
    ) -> None:
        self.registry = registry
        self.watchdog = watchdog
        self._logger = logger

    async def get_status(self, pid: int) -> dict[str, Any] | None:
        process_info = await self.registry.get_process(pid)
        if process_info is None:
            return None

        info_copy = process_info.copy()
        process = info_copy["process"]
        if process.returncode is None:
            info_copy["status"] = "running"
        else:
            info_copy["status"] = "finished"
            info_copy["exit_code"] = process.returncode
        return info_copy

    async def list_processes(self) -> list[dict[str, Any]]:
        pids = await self.registry.list_pids()
        results = await asyncio.gather(
            *(self.get_status(pid) for pid in pids),
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, dict)]

    async def get_statistics(self) -> dict[str, Any]:
        process_stats = await self.list_processes()
        watchdog_stats = await self.watchdog.get_stats()

        status_counts: dict[str, int] = {}
        for proc in process_stats:
            status = proc.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "processes": status_counts,
            "watchdog": watchdog_stats,
            "total_managed": len(process_stats),
        }

    async def cleanup_finished_processes(self) -> int:
        cleaned = 0
        pids = await self.registry.list_pids()
        for pid in pids:
            process_info = await self.registry.get_process(pid)
            if not process_info:
                continue
            process = process_info["process"]
            if process.returncode is not None:
                await self.registry.unregister(pid)
                await self.watchdog.unregister_process(pid)
                cleaned += 1

        if cleaned > 0:
            self._logger.debug(f"Cleaned up {cleaned} finished processes")
        return cleaned

    async def wait_for_completion(
        self, pid: int, timeout: float | None = None
    ) -> int | None:
        process_info = await self.registry.get_process(pid)
        if not process_info:
            return None

        process = process_info["process"]
        try:
            if timeout is None:
                await _wait_for_process_exit(process)
            else:
                await _wait_for_process_exit(process, timeout=timeout)
            return process.returncode
        except asyncio.TimeoutError:
            return process.returncode


class ProcessManager:
    """Fully asynchronous process manager."""

    def __init__(
        self,
        config: WatchdogConfig | None = None,
        config_dict: dict[str, Any] | None = None,
        *,
        watchdog: ProcessWatchdog | None = None,
        registry: ProcessRegistry | None = None,
        signal_handler: ProcessSignalHandler | None = None,
        lifecycle: ProcessLifecycleManager | None = None,
        monitor: ProcessMonitor | None = None,
        logger: logging.Logger | None = None,
    ):
        """Initialize the async process manager with injectable dependencies."""
        # Prefer injected collaborators when present
        inferred_logger = (
            logger
            or getattr(lifecycle, "_logger", None)
            or getattr(signal_handler, "_logger", None)
            or logging.getLogger(__name__)
        )

        if lifecycle is not None:
            registry = registry or lifecycle.registry
            signal_handler = signal_handler or lifecycle.signal_handler
            watchdog = watchdog or lifecycle.watchdog

        if monitor is not None:
            registry = registry or monitor.registry
            watchdog = watchdog or monitor.watchdog

        cfg = (
            WatchdogConfig.from_config(config_dict)
            if config_dict
            else config
            if config
            else WatchdogConfig()
        )
        self.config = cfg
        self.watchdog = watchdog or ProcessWatchdog(cfg)
        self._logger = inferred_logger
        self.registry = registry or ProcessRegistry()
        self.signal_handler = signal_handler or ProcessSignalHandler(
            self.registry, self._logger
        )
        self.lifecycle = lifecycle or ProcessLifecycleManager(
            self.watchdog, self.registry, self.signal_handler, self._logger
        )
        self.monitor = monitor or ProcessMonitor(
            self.registry, self.watchdog, self._logger
        )
        self._observers: list[Callable[[str, dict[str, Any]], None]] = []

    def add_observer(self, callback: Callable[[str, dict[str, Any]], None]) -> None:
        """Register an observer for process lifecycle events."""
        self._observers.append(callback)

    def _emit_event(self, event_name: str, **payload: Any) -> None:
        data = {"event": event_name, **payload}
        for cb in self._observers:
            try:
                cb(event_name, data)
            except Exception:
                self._logger.debug("ProcessManager observer failed", exc_info=True)
        self._logger.debug("[process_manager] %s: %s", event_name, payload)

    async def start_process(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        process = await self.lifecycle.start(config)
        self._emit_event(
            "started",
            pid=process.pid if hasattr(process, "pid") else None,
            process_name=config.name,
            command=config.command,
        )
        return process

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        result = await self.lifecycle.stop(pid, force=force)
        self._emit_event("stopped", pid=pid, force=force, result=result)
        return result

    async def stop_all_processes(self, force: bool = False) -> None:
        await self.lifecycle.stop_all(force=force)
        self._emit_event("stopped_all", force=force)

    async def get_process_status(self, pid: int) -> dict[str, Any] | None:
        return await self.monitor.get_status(pid)

    async def list_processes(self) -> list[dict[str, Any]]:
        return await self.monitor.list_processes()

    async def wait_for_process(
        self, pid: int, timeout: float | None = None
    ) -> int | None:
        return await self.monitor.wait_for_completion(pid, timeout=timeout)

    async def update_activity(self, pid: int) -> None:
        await self.watchdog.update_activity(pid)

    async def get_stats(self) -> dict[str, Any]:
        return await self.monitor.get_statistics()

    async def cleanup_finished_processes(self) -> int:
        return await self.monitor.cleanup_finished_processes()

    async def shutdown(self) -> None:
        self._logger.info("Shutting down process manager")
        await self.stop_all_processes()
        await self.watchdog.stop()
        await self.registry.clear()
        self._logger.info("Process manager shutdown complete")
        self._emit_event("shutdown")

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        process_info = await self.registry.get_process(pid)
        if not process_info:
            return False

        process = process_info["process"]
        name = process_info["config"].name

        try:
            if process.returncode is not None:
                return False

            result = await self.signal_handler.send(signal_type, pid, process_info)
            self._emit_event(
                "signal",
                pid=pid,
                signal=signal_type,
                process_name=name,
                result=result,
            )
            return result

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

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> dict[int, bool]:
        results: dict[int, bool] = {}
        pids = await self.registry.list_pids()
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

        self._emit_event(
            "signal_all",
            signal=signal_type,
            results=results,
            failures=failures if failures else None,
        )

        if failures:
            raise ProcessSignalError(
                f"Failed to send {signal_type} signal to some processes",
                context={"signal_type": signal_type, "failed_processes": failures},
            )

        return results

    async def is_process_registered(self, pid: int) -> bool:
        return await self.watchdog.is_process_registered(pid)

    async def register_existing_process(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        name: str,
        activity_callback: Callable[[], float] | None = None,
    ) -> None:
        await self.watchdog.register_process(pid, process, activity_callback, name)
        await self.registry.register(
            pid,
            process,
            ProcessConfig(
                command=[name],
                name=name,
                activity_callback=activity_callback,
            ),
        )
