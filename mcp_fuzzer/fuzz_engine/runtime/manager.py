#!/usr/bin/env python3
"""
Process Manager for MCP Fuzzer Runtime

This module wires together configuration, lifecycle, registry, signals, and monitoring
to provide a fully asynchronous process manager.
"""

import asyncio
import logging
from typing import Any, Callable

from ...exceptions import MCPError, ProcessSignalError
from .config import ProcessConfig
from .lifecycle import ProcessLifecycleManager
from .monitor import ProcessMonitor
from .registry import ProcessRegistry
from .signals import ProcessSignalHandler
from .watchdog import ProcessWatchdog, WatchdogConfig


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
        if lifecycle is not None:
            self.lifecycle = lifecycle
            self.lifecycle.watchdog = self.watchdog
            self.lifecycle.registry = self.registry
            self.lifecycle.signal_handler = self.signal_handler
        else:
            self.lifecycle = ProcessLifecycleManager(
                self.watchdog, self.registry, self.signal_handler, self._logger
            )

        if monitor is not None:
            self.monitor = monitor
            self.monitor.watchdog = self.watchdog
            self.monitor.registry = self.registry
        else:
            self.monitor = ProcessMonitor(
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
