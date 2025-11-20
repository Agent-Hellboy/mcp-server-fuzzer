#!/usr/bin/env python3
"""Clean CLI runner following SOLID principles with proper subsystem separation."""

import logging
from typing import Protocol

from .interfaces import CLIDependencies
from ..config.options import RunPlan

logger = logging.getLogger(__name__)


class SubsystemManager(Protocol):
    """Interface for managing a specific subsystem's lifecycle."""

    def initialize(self, plan: RunPlan) -> None:
        """Initialize the subsystem with the given run plan."""
        ...

    def cleanup(self) -> None:
        """Clean up the subsystem resources."""
        ...


class AuthManager:
    """Manages authentication subsystem lifecycle."""

    def __init__(self, auth_factory):
        self.auth_factory = auth_factory
        self.auth_manager = None

    def initialize(self, plan: RunPlan) -> None:
        """Initialize authentication manager."""
        self.auth_manager = self.auth_factory.create(plan.auth_options)

    def cleanup(self) -> None:
        """Clean up authentication resources."""
        # Auth managers typically don't need cleanup
        pass

    def get_auth_manager(self):
        """Get the current auth manager."""
        return self.auth_manager


class TransportManager:
    """Manages transport subsystem lifecycle."""

    def __init__(self, transport_factory, auth_manager):
        self.transport_factory = transport_factory
        self.auth_manager = auth_manager
        self.transport = None

    def initialize(self, plan: RunPlan) -> None:
        """Initialize transport with authentication."""
        self.transport = self.transport_factory.create_with_auth(
            plan.transport_options, self.auth_manager.get_auth_manager()
        )

    def cleanup(self) -> None:
        """Clean up transport resources."""
        if self.transport and hasattr(self.transport, 'close'):
            try:
                self.transport.close()
            except Exception as e:
                logger.warning(f"Error closing transport: {e}")

    def get_transport(self):
        """Get the current transport."""
        return self.transport


class SafetyManager:
    """Manages safety subsystem lifecycle."""

    def __init__(self, safety_controller, network_configurator):
        self.safety_controller = safety_controller
        self.network_configurator = network_configurator
        self.safety_system = None

    def initialize(self, plan: RunPlan) -> None:
        """Initialize safety system and network policies."""
        # Configure network policies first
        self.network_configurator.configure(plan.safety_options)

        # Configure safety system
        self.safety_system = self.safety_controller.configure(plan.safety_options)

        # Enable safety if requested
        if plan.safety_options.enabled:
            self.safety_controller.enable(self.safety_system)

    def cleanup(self) -> None:
        """Clean up safety system."""
        try:
            self.safety_controller.disable()
        except Exception as e:
            logger.warning(f"Error disabling safety system: {e}")

    def get_safety_system(self):
        """Get the current safety system."""
        return self.safety_system


class ReportingManager:
    """Manages reporting subsystem lifecycle."""

    def __init__(self, reporting_orchestrator, safety_system):
        self.reporting_orchestrator = reporting_orchestrator
        self.safety_system = safety_system
        self.reporter = None

    def initialize(self, plan: RunPlan) -> None:
        """Initialize reporting system."""
        self.reporter = self.reporting_orchestrator.create_reporter(
            plan.output_options, self.safety_system.get_safety_system()
        )

    def cleanup(self) -> None:
        """Clean up reporting resources."""
        # Reporters typically handle their own cleanup
        pass

    def get_reporter(self):
        """Get the current reporter."""
        return self.reporter


class SubsystemCoordinator:
    """Coordinates initialization and cleanup of all subsystems."""

    def __init__(self, dependencies: CLIDependencies):
        self.dependencies = dependencies
        self.managers = self._create_managers()

    def _create_managers(self) -> list[SubsystemManager]:
        """Create all subsystem managers in dependency order."""
        # Create auth manager first (no dependencies)
        auth_manager = AuthManager(self.dependencies.auth_factory)

        # Create safety manager (depends on network configurator)
        safety_manager = SafetyManager(
            self.dependencies.safety_controller,
            self.dependencies.network_configurator
        )

        # Create transport manager (depends on auth manager)
        transport_manager = TransportManager(
            self.dependencies.transport_factory,
            auth_manager
        )

        # Create reporting manager (depends on safety manager)
        reporting_manager = ReportingManager(
            self.dependencies.reporting_orchestrator,
            safety_manager
        )

        # Return in initialization order (reverse of dependency order for cleanup)
        return [auth_manager, safety_manager, transport_manager, reporting_manager]

    def initialize_all(self, plan: RunPlan) -> None:
        """Initialize all subsystems in the correct order."""
        for manager in self.managers:
            manager.initialize(plan)

    def cleanup_all(self) -> None:
        """Clean up all subsystems in reverse order."""
        for manager in reversed(self.managers):
            manager.cleanup()

    def get_auth_manager(self):
        """Get the auth manager for external access."""
        return self.managers[0].get_auth_manager()  # auth_manager is first

    def get_transport(self):
        """Get the transport for external access."""
        return self.managers[2].get_transport()  # transport_manager is third

    def get_safety_system(self):
        """Get the safety system for external access."""
        return self.managers[1].get_safety_system()  # safety_manager is second

    def get_reporter(self):
        """Get the reporter for external access."""
        return self.managers[3].get_reporter()  # reporting_manager is fourth


class Runner:
    """Clean CLI runner following Single Responsibility Principle."""

    def __init__(self, dependencies: CLIDependencies):
        self.dependencies = dependencies
        self.coordinator = SubsystemCoordinator(dependencies)

    def execute_plan(self, plan: RunPlan) -> int:
        """Execute fuzzing according to the run plan.

        This method follows SRP by focusing only on execution orchestration.
        Subsystem management is delegated to the coordinator.
        """
        try:
            # Initialize all subsystems
            self.coordinator.initialize_all(plan)

            # Execute fuzzing with initialized subsystems
            return self.dependencies.fuzzing_orchestrator.execute(plan)

        except Exception as e:
            logger.error(f"Execution failed: {e}")
            return 1
        finally:
            # Always clean up subsystems
            self.coordinator.cleanup_all()

