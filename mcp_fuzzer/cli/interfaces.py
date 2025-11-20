#!/usr/bin/env python3
"""Subsystem interfaces for dependency injection in CLI/runner."""

from __future__ import annotations

import argparse
from abc import ABC, abstractmethod
from typing import Any, Optional, Protocol

from ..config.options import (
    AuthOptions,
    OutputOptions,
    RunPlan,
    SafetyOptions,
    TransportOptions,
)


class AuthFactory(Protocol):
    """Interface for creating authentication managers."""

    def create(self, options: AuthOptions) -> Any:
        """Create an authentication manager from options."""
        ...


class TransportFactory(Protocol):
    """Interface for creating transport instances."""

    def create(self, options: TransportOptions) -> Any:
        """Create a transport instance from options."""
        ...

    def create_with_auth(self, options: TransportOptions, auth_manager: Any) -> Any:
        """Create a transport with authentication headers."""
        ...


class SafetyController(Protocol):
    """Interface for safety system management."""

    def configure(self, options: SafetyOptions) -> Any:
        """Configure and return a safety system instance."""
        ...

    def enable(self, safety_system: Any) -> None:
        """Enable the safety system for the current context."""
        ...

    def disable(self) -> None:
        """Disable the safety system."""
        ...


class NetworkPolicyConfigurator(Protocol):
    """Interface for configuring network policies."""

    def configure(self, safety_options: SafetyOptions) -> None:
        """Configure network policies based on safety options."""
        ...


class ReportingOrchestrator(Protocol):
    """Interface for managing reporting and output."""

    def create_reporter(
        self, options: OutputOptions, safety_system: Optional[Any] = None
    ) -> Any:
        """Create a reporter instance."""
        ...


class LoopManager(Protocol):
    """Interface for managing async event loops and signal handling."""

    def run_async(self, coro) -> Any:
        """Run an async coroutine with proper loop management."""
        ...

    def setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        ...


class FuzzingOrchestrator(ABC):
    """Abstract base for fuzzing execution orchestration."""

    @abstractmethod
    def execute(self, plan: RunPlan) -> int:
        """Execute fuzzing according to the run plan."""
        ...

    @abstractmethod
    def validate_transport(self, transport: Any) -> bool:
        """Validate that transport configuration is correct."""
        ...


# Command Pattern for CLI Operations
class CLICommand(Protocol):
    """Interface for CLI commands (utility operations that exit early)."""

    def can_handle(self, args) -> bool:
        """Check if this command can handle the given arguments."""
        ...

    def execute(self, args) -> None:
        """Execute the command. Should exit the process when done."""
        ...


class CLIExecutionStrategy(Protocol):
    """Interface for different CLI execution strategies (fuzzing modes)."""

    def can_handle(self, args) -> bool:
        """Check if this strategy can handle the given arguments."""
        ...

    def execute(self, args, config: dict[str, Any]) -> int:
        """Execute the fuzzing operation and return exit code."""
        ...


class CLIArgumentParser(Protocol):
    """Interface for argument parsing."""

    def parse(self, argv: list[str] | None = None) -> argparse.Namespace:
        """Parse command line arguments."""
        ...

    def validate(self, args: argparse.Namespace) -> None:
        """Validate parsed arguments."""
        ...


class CLIConfigurationLoader(Protocol):
    """Interface for loading CLI configuration."""

    def load(self, args: argparse.Namespace) -> dict[str, Any]:
        """Load configuration from arguments, files, and environment."""
        ...


class CLIDependencyFactory(Protocol):
    """Interface for creating CLI dependencies."""

    def create_dependencies(self) -> CLIDependencies:
        """Create and wire all CLI subsystem dependencies."""
        ...


class CLIDependencies:
    """Container for all CLI subsystem dependencies."""

    def __init__(
        self,
        auth_factory: AuthFactory,
        transport_factory: TransportFactory,
        safety_controller: SafetyController,
        network_configurator: NetworkPolicyConfigurator,
        reporting_orchestrator: ReportingOrchestrator,
        loop_manager: LoopManager,
        fuzzing_orchestrator: FuzzingOrchestrator,
    ):
        self.auth_factory = auth_factory
        self.transport_factory = transport_factory
        self.safety_controller = safety_controller
        self.network_configurator = network_configurator
        self.reporting_orchestrator = reporting_orchestrator
        self.loop_manager = loop_manager
        self.fuzzing_orchestrator = fuzzing_orchestrator
