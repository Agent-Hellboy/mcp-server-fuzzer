#!/usr/bin/env python3
"""
Signal strategy helpers for MCP Fuzzer runtime.
"""

import logging
import os
import signal
from typing import Any, Protocol

from .registry import ManagedProcessInfo, ProcessRegistry


class ProcessSignalStrategy(Protocol):
    """Strategy interface for sending signals to processes."""

    async def send(
        self, pid: int, process_info: ManagedProcessInfo | None = None
    ) -> bool: ...


class _BaseSignalStrategy:
    """Shared helpers for concrete signal strategies."""

    def __init__(self, registry: ProcessRegistry, logger: logging.Logger) -> None:
        self._registry = registry
        self._logger = logger

    async def _resolve_process(
        self, pid: int, process_info: ManagedProcessInfo | None = None
    ) -> tuple[Any, str] | tuple[None, None]:
        info = process_info or await self._registry.get_process(pid)
        if not info:
            return None, None
        process = info["process"]
        name = info["config"].name
        return process, name


class TermSignalStrategy(_BaseSignalStrategy):
    async def send(
        self, pid: int, process_info: ManagedProcessInfo | None = None
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
        self, pid: int, process_info: ManagedProcessInfo | None = None
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
        self, pid: int, process_info: ManagedProcessInfo | None = None
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
        self._signal_map: dict[str, ProcessSignalStrategy] = {}
        self.register_strategy("timeout", TermSignalStrategy(registry, logger))
        self.register_strategy("force", KillSignalStrategy(registry, logger))
        self.register_strategy("interrupt", InterruptSignalStrategy(registry, logger))

    def register_strategy(self, name: str, strategy: ProcessSignalStrategy) -> None:
        """Register or override a signal strategy."""
        self._signal_map[name] = strategy

    async def send(
        self, signal_type: str, pid: int, process_info: ManagedProcessInfo | None = None
    ) -> bool:
        handler = self._signal_map.get(signal_type)
        if handler is None:
            self._logger.warning(f"Unknown signal type: {signal_type}")
            return False
        return await handler.send(pid, process_info)
