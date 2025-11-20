#!/usr/bin/env python3
"""Concrete implementations of CLI subsystem interfaces."""

import logging
# No typing imports needed

from .interfaces import (
    AuthFactory,
    TransportFactory,
    SafetyController,
    NetworkPolicyConfigurator,
    ReportingOrchestrator,
    FuzzingOrchestrator,
)
from .loop_manager import LoopManager
from ..auth import AuthManager
from ..transport import create_transport
from ..safety_system.safety import SafetyFilter
from ..safety_system.policy import configure_network_policy
from ..reports.reporter import FuzzerReporter
from ..config.options import RunPlan, TransportOptions

logger = logging.getLogger(__name__)


class DefaultAuthFactory(AuthFactory):
    """Default implementation of AuthFactory."""

    def create(self, options):
        """Create an AuthManager from options."""
        if not options.providers:
            return None

        # Create AuthManager from providers config
        # This is a simplified implementation - the real one would be more complex
        return AuthManager(providers_config=options.providers)


class DefaultTransportFactory(TransportFactory):
    """Default implementation of TransportFactory."""

    def create(self, options: TransportOptions):
        """Create a transport instance."""
        return create_transport(
            protocol=options.protocol,
            endpoint=options.endpoint,
            timeout=options.timeout,
        )

    def create_with_auth(self, options: TransportOptions, auth_manager):
        """Create a transport with authentication."""
        transport = self.create(options)

        # Apply auth headers if available
        if auth_manager and hasattr(transport, 'add_headers'):
            auth_headers = auth_manager.get_default_auth_headers()
            if auth_headers:
                transport.add_headers(auth_headers)
                logger.debug(f"Applied {len(auth_headers)} auth headers to transport")

        return transport


class DefaultSafetyController(SafetyController):
    """Default implementation of SafetyController."""

    def __init__(self):
        self._safety_system = None

    def configure(self, options):
        """Configure safety system."""
        if not options.enabled:
            return None

        safety_system = SafetyFilter()
        if options.fs_root:
            safety_system.set_fs_root(options.fs_root)

        self._safety_system = safety_system
        return safety_system

    def enable(self, safety_system):
        """Enable safety system."""
        if safety_system and hasattr(safety_system, 'enable'):
            safety_system.enable()

    def disable(self):
        """Disable safety system."""
        if self._safety_system and hasattr(self._safety_system, 'disable'):
            self._safety_system.disable()


class DefaultNetworkPolicyConfigurator(NetworkPolicyConfigurator):
    """Default implementation of NetworkPolicyConfigurator."""

    def configure(self, safety_options):
        """Configure network policies."""
        configure_network_policy(
            allow_hosts=safety_options.allow_hosts,
            no_network=safety_options.no_network,
        )


class DefaultReportingOrchestrator(ReportingOrchestrator):
    """Default implementation of ReportingOrchestrator."""

    def create_reporter(self, options, safety_system=None):
        """Create a reporter instance."""
        if not options.output_dir:
            return None

        return FuzzerReporter(
            output_dir=options.output_dir,
            safety_system=safety_system,
        )


class DefaultFuzzingOrchestrator(FuzzingOrchestrator):
    """Default implementation of FuzzingOrchestrator."""

    def __init__(self, loop_manager: LoopManager):
        self.loop_manager = loop_manager

    def execute(self, plan: RunPlan) -> int:
        """Execute fuzzing according to the run plan."""
        # This would implement the actual fuzzing logic
        # For now, return success
        logger.info(f"Executing fuzzing plan: {plan.runtime_options.mode}")
        return 0

    def validate_transport(self, transport) -> bool:
        """Validate transport configuration."""
        # Basic validation - could be more sophisticated
        return transport is not None
