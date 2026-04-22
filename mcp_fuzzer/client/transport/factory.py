#!/usr/bin/env python3
"""Transport factory that layers auth resolution on top of the base registry."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from ...transport.catalog import build_driver as base_build_driver
from ...transport.wrappers import RetryingTransport, RetryPolicy
from ...exceptions import TransportRegistrationError
from ...types import AuthManagerProtocol

logger = logging.getLogger(__name__)
AUTH_PROTOCOLS = ("http", "https", "streamablehttp", "sse")


@dataclass(frozen=True)
class TransportBuildRequest:
    """Typed transport settings used by the client runtime."""

    protocol: str
    endpoint: str
    timeout: float = 30.0
    transport_retries: int = 1
    transport_retry_delay: float = 0.5
    transport_retry_backoff: float = 2.0
    transport_retry_max_delay: float = 5.0
    transport_retry_jitter: float = 0.1
    auth_manager: AuthManagerProtocol | None = None
    safety_enabled: bool = True


def build_driver_with_auth(request: TransportBuildRequest):
    """Create a transport with authentication headers when available."""
    resolved = request
    try:
        auth_headers = None
        auth_manager = resolved.auth_manager

        if auth_manager:
            auth_headers = auth_manager.get_default_auth_headers()
            if not auth_headers:
                auth_headers = auth_manager.get_auth_headers_for_tool(
                    ""
                )  # pragma: no cover
            if auth_headers:
                logger.debug(
                    "Auth headers found for transport: %s",
                    list(auth_headers.keys()),
                )
            else:
                logger.debug(
                    "No auth headers found for default tool mapping"
                )  # pragma: no cover

        factory_kwargs = {"timeout": resolved.timeout}
        safety_enabled = resolved.safety_enabled

        if resolved.protocol in AUTH_PROTOCOLS:
            factory_kwargs["safety_enabled"] = safety_enabled
        if resolved.protocol in AUTH_PROTOCOLS and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers
            logger.debug(
                "Adding auth headers to %s transport", resolved.protocol.upper()
            )

        logger.debug(
            "Creating %s transport to %s",
            resolved.protocol.upper(),
            resolved.endpoint,
        )
        transport = base_build_driver(
            resolved.protocol,
            resolved.endpoint,
            **factory_kwargs,
        )
        retry_attempts = resolved.transport_retries
        try:
            retry_attempts = int(retry_attempts)
        except (TypeError, ValueError):
            retry_attempts = 1
        if retry_attempts > 1:
            policy = RetryPolicy(
                max_attempts=retry_attempts,
                base_delay=resolved.transport_retry_delay,
                max_delay=resolved.transport_retry_max_delay,
                backoff_factor=resolved.transport_retry_backoff,
                jitter=resolved.transport_retry_jitter,
            )
            transport = RetryingTransport(transport, policy=policy)
        return transport
    except Exception as transport_error:  # pragma: no cover
        logger.exception("Transport creation failed")
        raise TransportRegistrationError(
            "Transport creation failed",
            context={
                "protocol": getattr(resolved, "protocol", "unknown"),
                "endpoint": getattr(resolved, "endpoint", "unknown"),
                "details": str(transport_error),
            },
        ) from transport_error


__all__ = ["TransportBuildRequest", "build_driver_with_auth"]
