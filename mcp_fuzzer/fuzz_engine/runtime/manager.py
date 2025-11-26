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
from .config import ProcessConfig, WatchdogConfig
from .lifecycle import ProcessLifecycle
from .monitor import ProcessInspector
from .registry import ProcessRegistry
from .signals import ProcessSignalStrategy, SignalDispatcher
from .watchdog import ProcessWatchdog


class ProcessManager:
    """Fully asynchronous process manager."""

    def __init__(
        self,
        watchdog: ProcessWatchdog,
        registry: ProcessRegistry,
        signal_handler: SignalDispatcher,
        lifecycle: ProcessLifecycle,
        monitor: ProcessInspector,
        logger: logging.Logger,
    ):
        """Initialize with fully constructed dependencies."""
        self.watchdog = watchdog
        self.registry = registry
        self.signal_dispatcher = signal_handler
        self.lifecycle = lifecycle
        self.monitor = monitor
        self._logger = logger
        self._observers: list[Callable[[str, dict[str, Any]], None]] = []
        
        # Ensure lifecycle and monitor have the correct watchdog reference
        if self.lifecycle.watchdog is not self.watchdog:
            self.lifecycle.watchdog = self.watchdog
        if self.monitor.watchdog is not self.watchdog:
            self.monitor.watchdog = self.watchdog

    @classmethod
    def from_config(
        cls,
        config: WatchdogConfig | None = None,
        config_dict: dict[str, Any] | None = None,
        logger: logging.Logger | None = None,
        *,
        signal_strategies: dict[str, ProcessSignalStrategy] | None = None,
        register_default_signal_strategies: bool = True,
    ) -> "ProcessManager":
        """Factory method for creating a ProcessManager with default components.
        
        Args:
            config: Optional WatchdogConfig instance
            config_dict: Optional dict to create WatchdogConfig from
            logger: Optional logger instance
            signal_strategies: Optional custom signal strategies to register.
                If provided, these will be registered before defaults (unless
                register_default_signal_strategies=False).
            register_default_signal_strategies: If True (default), register built-in
                strategies (timeout, force, interrupt). Set to False to use only
                custom strategies.
        """
        cfg = (
            WatchdogConfig.from_config(config_dict)
            if config_dict
            else config
            if config
            else WatchdogConfig()
        )
        resolved_logger = logger or logging.getLogger(__name__)
        watchdog = ProcessWatchdog(cfg)
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(
            registry,
            resolved_logger,
            strategies=signal_strategies,
            register_defaults=register_default_signal_strategies,
        )
        lifecycle = ProcessLifecycle(
            watchdog, registry, signal_handler, resolved_logger
        )
        monitor = ProcessInspector(registry, watchdog, resolved_logger)
        return cls(
            watchdog, registry, signal_handler, lifecycle, monitor, resolved_logger
        )

    def add_observer(self, callback: Callable[[str, dict[str, Any]], None]) -> None:
        """Register an observer for process lifecycle events."""
        self._observers.append(callback)

    def _emit_event(self, event_name: str, **payload: Any) -> None:
        data = {"event": event_name, **payload}
        for cb in self._observers:
            try:
                cb(event_name, data)
            except Exception:
                self._logger.warning("ProcessManager observer failed", exc_info=True)
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

    async def wait(self, pid: int, timeout: float | None = None) -> int | None:
        return await self.monitor.wait_for_completion(pid, timeout=timeout)

    async def update_activity(self, pid: int) -> None:
        await self.watchdog.update_activity(pid)

    async def get_stats(self) -> dict[str, Any]:
        return await self.monitor.get_statistics()

    async def cleanup_finished_processes(self) -> int:
        return await self.monitor.cleanup_finished_processes()

    async def shutdown(self) -> None:
        self._logger.info("Shutting down process manager")
        try:
            await self.stop_all_processes()
        except Exception:
            self._logger.error("Failed to stop all processes", exc_info=True)
            raise
        finally:
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

            result = await self.signal_dispatcher.send(signal_type, pid, process_info)
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
