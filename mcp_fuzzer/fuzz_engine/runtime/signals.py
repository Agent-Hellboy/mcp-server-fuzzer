#!/usr/bin/env python3
"""
Signal strategy helpers for MCP Fuzzer runtime.
"""

import logging
import os
import signal
from typing import Any, Protocol

from .registry import ProcessRecord, ProcessRegistry


class ProcessSignalStrategy(Protocol):
    """Strategy interface for sending signals to processes."""

    async def send(
        self, pid: int, process_info: ProcessRecord | None = None
    ) -> bool: ...


class _BaseSignalStrategy:
    """Shared helpers for concrete signal strategies."""

    def __init__(self, registry: ProcessRegistry, logger: logging.Logger) -> None:
        self._registry = registry
        self._logger = logger

    async def _resolve_process(
        self, pid: int, process_info: ProcessRecord | None = None
    ) -> tuple[Any, str] | tuple[None, None]:
        info = process_info or await self._registry.get_process(pid)
        if not info:
            return None, None
        process = info["process"]
        name = info["config"].name
        return process, name


class TermSignalStrategy(_BaseSignalStrategy):
    async def send(self, pid: int, process_info: ProcessRecord | None = None) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if process is None:
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
    async def send(self, pid: int, process_info: ProcessRecord | None = None) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if process is None:
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
    async def send(self, pid: int, process_info: ProcessRecord | None = None) -> bool:
        process, name = await self._resolve_process(pid, process_info)
        if process is None:
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


class SignalDispatcher:
    """SINGLE responsibility: Send signals to processes using pluggable strategies.

    Supports dependency injection of custom signal strategies, allowing extension
    without modifying the core implementation. Default strategies (timeout, force,
    interrupt) are registered automatically unless custom strategies are provided.

    Example:
        # Use default strategies
        dispatcher = SignalDispatcher(registry, logger)

        # Use custom strategies via dependency injection
        custom_strategies = {
            "timeout": CustomTermStrategy(registry, logger),
            "force": CustomKillStrategy(registry, logger),
        }
        dispatcher = SignalDispatcher(
            registry, logger, strategies=custom_strategies
        )

        # Or register strategies after creation
        dispatcher.register_strategy("custom", MyCustomStrategy(registry, logger))
    """

    def __init__(
        self,
        registry: ProcessRegistry,
        logger: logging.Logger,
        strategies: dict[str, ProcessSignalStrategy] | None = None,
        register_defaults: bool = True,
    ) -> None:
        """Initialize SignalDispatcher with optional custom strategies.

        Args:
            registry: Process registry for resolving process information
            logger: Logger instance for signal operations
            strategies: Optional dict of custom strategies to register.
                If provided, these will override default strategies with matching
                keys (timeout, force, interrupt). Custom strategies are registered
                after defaults, allowing them to replace built-in implementations.
            register_defaults: If True (default), register built-in strategies
                (timeout, force, interrupt). Set to False to use only custom
                strategies.
        """
        self._registry = registry
        self._logger = logger
        self._signal_map: dict[str, ProcessSignalStrategy] = {}

        # Register default strategies first (unless disabled)
        if register_defaults:
            self.register_strategy("timeout", TermSignalStrategy(registry, logger))
            self.register_strategy("force", KillSignalStrategy(registry, logger))
            self.register_strategy(
                "interrupt", InterruptSignalStrategy(registry, logger)
            )

        # Register custom strategies (if provided) - these override defaults
        if strategies:
            for name, strategy in strategies.items():
                self.register_strategy(name, strategy)

    @classmethod
    def from_config(
        cls,
        registry: ProcessRegistry,
        logger: logging.Logger,
        strategies: dict[str, ProcessSignalStrategy] | None = None,
        register_defaults: bool = True,
    ) -> "SignalDispatcher":
        """Factory method for creating SignalDispatcher with configuration.

        This method provides a consistent way to create SignalDispatcher instances
        and is useful for dependency injection scenarios.

        Args:
            registry: Process registry for resolving process information
            logger: Logger instance for signal operations
            strategies: Optional dict of custom strategies to register
            register_defaults: If True (default), register built-in strategies

        Returns:
            Configured SignalDispatcher instance

        Example:
            # Create with custom strategies only
            dispatcher = SignalDispatcher.from_config(
                registry, logger,
                strategies={"custom": MyStrategy(registry, logger)},
                register_defaults=False
            )
        """
        return cls(registry, logger, strategies, register_defaults)

    def register_strategy(self, name: str, strategy: ProcessSignalStrategy) -> None:
        """Register or override a signal strategy.

        This method allows runtime registration of signal strategies, enabling
        extension and customization without modifying the core implementation.

        Args:
            name: Strategy identifier (e.g., "timeout", "force", "interrupt")
            strategy: Strategy implementation conforming to ProcessSignalStrategy

        Example:
            class CustomStrategy(ProcessSignalStrategy):
                async def send(self, pid: int, process_info=None) -> bool:
                    # Custom signal handling logic
                    return True

            dispatcher.register_strategy("custom", CustomStrategy())
            # Override default strategy
            dispatcher.register_strategy("timeout", CustomTermStrategy())
        """
        self._signal_map[name] = strategy
        self._logger.debug(f"Registered signal strategy: {name}")

    def unregister_strategy(self, name: str) -> bool:
        """Unregister a signal strategy.

        Args:
            name: Strategy identifier to remove

        Returns:
            True if strategy was removed, False if it didn't exist
        """
        if name in self._signal_map:
            del self._signal_map[name]
            self._logger.debug(f"Unregistered signal strategy: {name}")
            return True
        return False

    def list_strategies(self) -> list[str]:
        """List all registered strategy names.

        Returns:
            List of registered strategy identifiers
        """
        return list(self._signal_map.keys())

    async def send(
        self, signal_type: str, pid: int, process_info: ProcessRecord | None = None
    ) -> bool:
        """Send a signal to a process using the specified strategy.

        Args:
            signal_type: Strategy identifier (e.g., "timeout", "force", "interrupt")
            pid: Process ID to signal
            process_info: Optional process record (will be resolved if not provided)

        Returns:
            True if signal was sent successfully, False otherwise

        Raises:
            Logs warning if signal_type is not registered
        """
        handler = self._signal_map.get(signal_type)
        if handler is None:
            self._logger.warning(
                f"Unknown signal type: {signal_type}. "
                f"Available strategies: {self.list_strategies()}"
            )
            return False
        return await handler.send(pid, process_info)
