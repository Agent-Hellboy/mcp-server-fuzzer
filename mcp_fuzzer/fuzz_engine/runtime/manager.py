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
from ...events import ProcessEventObserver
from .config import ProcessConfig, WatchdogConfig
from .lifecycle import ProcessLifecycle
from .monitor import ProcessCompletionResult, ProcessInspector
from .registry import ProcessRegistry
from .signals import ProcessSignalStrategy, SignalDispatcher
from .watchdog import ProcessWatchdog


class _ProcessManagerMeta(type):
    def __instancecheck__(cls, instance: object) -> bool:
        if type.__instancecheck__(cls, instance):
            return True
        inst_cls = getattr(instance, "__class__", None)
        if inst_cls is None:
            return False
        return (
            inst_cls.__name__ == cls.__name__
            and inst_cls.__module__ == cls.__module__
        )


class ProcessManager(metaclass=_ProcessManagerMeta):
    """Fully asynchronous process manager.

    Events:

    * ``started`` – emitted by ``start_process`` with payload keys ``pid``,
      ``process_name``, and ``command``.
    * ``stopped`` – emitted by ``stop_process`` with payload keys ``pid``, ``force``,
      and ``result``.
    * ``stopped_all`` – emitted after ``stop_all_processes`` completes with
      ``force`` in the payload.
    * ``shutdown`` / ``shutdown_failed`` – emitted during shutdown; ``shutdown_failed``
      includes ``{"error": str(exception)}``.
    * ``signal`` / ``signal_all`` – emitted when signals are dispatched; payload
      keys include the target PID, signal name, and results (``signal_all`` adds
      ``"results"`` and ``"failures"``).
    """

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
        self._watchdog = watchdog
        self.registry = registry
        self.signal_dispatcher = signal_handler
        self.lifecycle = lifecycle
        self.monitor = monitor
        self._logger = logger
        self._observers: list[ProcessEventObserver] = []
        self._align_dependencies()

    @classmethod
    def with_dependencies(
        cls,
        watchdog: ProcessWatchdog,
        registry: ProcessRegistry,
        signal_handler: SignalDispatcher,
        lifecycle: ProcessLifecycle,
        monitor: ProcessInspector,
        logger: logging.Logger,
    ) -> "ProcessManager":
        """Factory to align collaborators before constructing a manager."""
        manager = cls(watchdog, registry, signal_handler, lifecycle, monitor, logger)
        manager._align_dependencies()
        return manager

    def _align_dependencies(self) -> None:
        """Ensure lifecycle and monitor share the manager's watchdog."""
        if getattr(self.lifecycle, "watchdog", None) is not self._watchdog:
            self.lifecycle.watchdog = self._watchdog
        if getattr(self.monitor, "watchdog", None) is not self._watchdog:
            self.monitor.watchdog = self._watchdog

    @property
    def watchdog(self) -> ProcessWatchdog:
        """The currently active process watchdog."""
        return self._watchdog

    @watchdog.setter
    def watchdog(self, value: ProcessWatchdog) -> None:
        self._watchdog = value
        self._align_dependencies()

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
            config: Optional WatchdogConfig instance.
            config_dict: Optional mapping used to create a WatchdogConfig; when both
                ``config`` and ``config_dict`` are provided, ``config_dict`` takes
                precedence.
            logger: Optional logger instance.
            signal_strategies: Optional custom signal strategies to register. If
                provided, these are registered before defaults (unless
                ``register_default_signal_strategies`` is ``False``).
            register_default_signal_strategies: If ``True`` (default), register
                built-in strategies (``timeout``, ``force``, ``interrupt``). Set
                to ``False`` to use only custom strategies.
        """
        cfg = (
            WatchdogConfig.from_config(config_dict)
            if config_dict
            else config
            if config
            else WatchdogConfig()
        )
        resolved_logger = logger or logging.getLogger(__name__)
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(
            registry,
            resolved_logger,
            strategies=signal_strategies,
            register_defaults=register_default_signal_strategies,
        )
        watchdog = ProcessWatchdog(
            registry, signal_handler, cfg, logger=resolved_logger
        )
        lifecycle = ProcessLifecycle(
            watchdog, registry, signal_handler, resolved_logger
        )
        monitor = ProcessInspector(registry, watchdog, resolved_logger)
        return cls.with_dependencies(
            watchdog, registry, signal_handler, lifecycle, monitor, resolved_logger
        )

    def add_observer(self, callback: ProcessEventObserver) -> None:
        """Register an observer for process lifecycle events."""
        self._observers.append(callback)

    def _emit_event(self, event_name: str, **payload: Any) -> None:
        data = {"event": event_name, **payload}
        for cb in self._observers:
            try:
                cb(event_name, data)
            except Exception:
                self._logger.warning(
                    "ProcessManager observer %r failed for event %s",
                    cb,
                    event_name,
                    exc_info=True,
                )
        self._logger.debug("[process_manager] %s: %s", event_name, payload)

    async def start_process(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        """Start a process and emit ``'started'`` event on success."""
        process = await self.lifecycle.start(config)
        self._emit_event(
            "started",
            pid=process.pid if hasattr(process, "pid") else None,
            process_name=config.name,
            command=config.command,
        )
        return process

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        """Request a graceful or forced stop and emit ``'stopped'``."""
        result = await self.lifecycle.stop(pid, force=force)
        self._emit_event("stopped", pid=pid, force=force, result=result)
        return result

    async def stop_all_processes(self, force: bool = False) -> None:
        """Stop every managed process and emit ``'stopped_all'``."""
        await self.lifecycle.stop_all(force=force)
        self._emit_event("stopped_all", force=force)

    async def get_process_status(self, pid: int) -> dict[str, Any] | None:
        """Return runtime status for the specified process."""
        return await self.monitor.get_status(pid)

    async def list_processes(self) -> list[dict[str, Any]]:
        """Return the current snapshot of managed processes."""
        return await self.monitor.list_processes()

    async def wait(
        self,
        pid: int,
        timeout: float | None = None,
    ) -> ProcessCompletionResult | None:
        """Wait for a process to finish (or timeout) and return a completion record."""
        return await self.monitor.wait_for_completion(pid, timeout=timeout)

    async def update_activity(self, pid: int) -> None:
        """Update the watchdog activity timestamp for a running process."""
        await self.watchdog.update_activity(pid)

    async def get_stats(self) -> dict[str, Any]:
        """Return aggregated statistics from the monitor/watchdog."""
        return await self.monitor.get_statistics()

    async def cleanup_finished_processes(self) -> int:
        """Clean up finished processes from the registry/watchdog."""
        return await self.monitor.cleanup_finished_processes()

    async def shutdown(self) -> None:
        """Gracefully stop all processes, stop the watchdog,
        and emit shutdown events."""
        self._logger.info("Shutting down process manager")
        try:
            await self.stop_all_processes()
        except Exception as exc:
            self._logger.error("Failed to stop all processes", exc_info=True)
            self._emit_event("shutdown_failed", error=str(exc))
            raise
        finally:
            await self.watchdog.stop()
            await self.registry.clear()
        self._logger.info("Process manager shutdown complete")
        self._emit_event("shutdown")

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        """Send a signal to an individual process and emit ``'signal'``."""
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
        """Send the provided signal to every registered process and emit events.

        Raises:
            ProcessSignalError: if any of the signal dispatches failed.
        """
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
        """Return ``True`` when the registry still tracks the PID."""
        process = await self.registry.get_process(pid)
        return process is not None

    async def register_existing_process(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        name: str | None = None,
        activity_callback: Callable[[], float] | None = None,
        *,
        config: ProcessConfig | None = None,
    ) -> None:
        """Register a process that was created outside the manager.

        The watchdog is notified and a best-effort :class:`ProcessConfig` is
        computed when none is provided.
        """
        process_config = config or ProcessConfig(
            command=[name or str(pid)],
            name=name or "unknown",
            activity_callback=activity_callback,
        )
        if activity_callback and process_config.activity_callback is None:
            process_config.activity_callback = activity_callback
        if name and process_config.name in ("unknown", None):
            process_config.name = name
        if not getattr(process_config, "command", None):
            process_config.command = [name or str(pid)]

        await self.registry.register(
            pid,
            process,
            process_config,
        )
        await self.watchdog.update_activity(pid)
