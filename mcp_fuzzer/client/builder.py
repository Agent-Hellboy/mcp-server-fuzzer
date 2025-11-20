#!/usr/bin/env python3
"""Client Builder using Builder Pattern for dependency injection."""

from typing import Any, Optional, Protocol

from ..auth import AuthManager
from ..reports import FuzzerReporter
from ..safety_system.safety import SafetyProvider, SafetyFilter
from ..transport import TransportProtocol

from .base import MCPFuzzerClient
from .tool_client import ToolClient
from .protocol_client import ProtocolClient


class ClientDependencies(Protocol):
    """Protocol for client dependency injection."""

    @property
    def transport(self) -> TransportProtocol:
        ...

    @property
    def auth_manager(self) -> Optional[AuthManager]:
        ...

    @property
    def reporter(self) -> Optional[FuzzerReporter]:
        ...

    @property
    def safety_system(self) -> Optional[SafetyProvider]:
        ...

    @property
    def tool_timeout(self) -> Optional[float]:
        ...

    @property
    def max_concurrency(self) -> int:
        ...


class ClientBuilder:
    """Builder for constructing MCP Fuzzer clients with proper dependency injection."""

    def __init__(self):
        self._transport: Optional[TransportProtocol] = None
        self._auth_manager: Optional[AuthManager] = None
        self._reporter: Optional[FuzzerReporter] = None
        self._safety_system: Optional[SafetyProvider] = None
        self._tool_timeout: Optional[float] = None
        self._max_concurrency: int = 5
        self._safety_enabled: bool = True

    def with_transport(self, transport: TransportProtocol):
        """Set the transport."""
        self._transport = transport
        return self

    def with_auth_manager(self, auth_manager: AuthManager):
        """Set the authentication manager."""
        self._auth_manager = auth_manager
        return self

    def with_reporter(self, reporter: FuzzerReporter):
        """Set the reporter."""
        self._reporter = reporter
        return self

    def with_safety_system(self, safety_system: SafetyProvider):
        """Set the safety system."""
        self._safety_system = safety_system
        return self

    def with_tool_timeout(self, timeout: float):
        """Set the tool timeout."""
        self._tool_timeout = timeout
        return self

    def with_max_concurrency(self, concurrency: int):
        """Set the maximum concurrency."""
        self._max_concurrency = concurrency
        return self

    def with_safety_enabled(self, enabled: bool):
        """Enable or disable safety."""
        self._safety_enabled = enabled
        return self

    def build(self) -> MCPFuzzerClient:
        """Build the MCP Fuzzer client with all configured dependencies."""
        if not self._transport:
            raise ValueError("Transport is required")

        # Create safety system if enabled but not provided
        safety_system = self._safety_system
        if self._safety_enabled and not safety_system:
            safety_system = SafetyFilter()

        # Create tool client
        tool_client = ToolClient(
            transport=self._transport,
            auth_manager=self._auth_manager,
            safety_system=safety_system,
            max_concurrency=self._max_concurrency,
            enable_safety=self._safety_enabled,
        )

        # Create protocol client
        protocol_client = ProtocolClient(
            transport=self._transport,
            auth_manager=self._auth_manager,
            safety_system=safety_system,
            max_concurrency=self._max_concurrency,
            enable_safety=self._safety_enabled,
        )

        # Create main client
        return MCPFuzzerClient(
            transport=self._transport,
            auth_manager=self._auth_manager,
            tool_timeout=self._tool_timeout,
            reporter=self._reporter,
            safety_system=safety_system,
            safety_enabled=self._safety_enabled,
            max_concurrency=self._max_concurrency,
            tool_client=tool_client,
            protocol_client=protocol_client,
        )


class ClientFactory:
    """Factory for creating clients from configuration."""

    @staticmethod
    def create_from_config(config: dict[str, Any]) -> MCPFuzzerClient:
        """Create a client from configuration dictionary."""
        from ..transport import create_transport_with_auth
        from ..config import build_views_from_dict

        # Build views from config
        views = build_views_from_dict(config)

        # Create transport with auth
        transport_settings = views.transport
        class Args:
            def __init__(self, protocol, endpoint, timeout):
                self.protocol = protocol
                self.endpoint = endpoint
                self.timeout = timeout

        args = Args(
            protocol=transport_settings.protocol,
            endpoint=transport_settings.endpoint,
            timeout=transport_settings.timeout,
        )

        client_args = {"auth_manager": config.get("auth_manager")}
        transport = create_transport_with_auth(args, client_args)

        # Create safety system
        safety_settings = views.safety
        safety_enabled = safety_settings.enabled
        safety_system = None
        if safety_enabled:
            safety_system = SafetyFilter()
            fs_root = safety_settings.fs_root
            if fs_root:
                try:
                    safety_system.set_fs_root(fs_root)
                except Exception as e:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Failed to set filesystem root '{fs_root}': {e}")

        # Create reporter
        output_settings = views.output
        reporter = None
        if output_settings.output_dir:
            from ..reports import FuzzerReporter
            reporter = FuzzerReporter(
                output_dir=output_settings.output_dir,
                safety_system=safety_system
            )

        # Build client using builder
        return (
            ClientBuilder()
            .with_transport(transport)
            .with_auth_manager(config.get("auth_manager"))
            .with_reporter(reporter)
            .with_safety_system(safety_system)
            .with_tool_timeout(config.get("tool_timeout"))
            .with_max_concurrency(config.get("max_concurrency", 5))
            .with_safety_enabled(safety_enabled)
            .build()
        )
