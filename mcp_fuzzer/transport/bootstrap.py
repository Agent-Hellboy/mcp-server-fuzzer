#!/usr/bin/env python3
"""Transport bootstrap that layers auth resolution on top of the base registry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import logging
import os

from ..exceptions import TransportRegistrationError
from ..transport.catalog import build_driver as base_build_driver
from ..transport.retrying import RetryingTransport, RetryPolicy
from ..types import AuthManagerProtocol

logger = logging.getLogger(__name__)
AUTH_PROTOCOLS = ("http", "https", "streamablehttp", "sse")
STREAMABLE_HTTP_PROTOCOL_VERSION = "2025-03-26"


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


def _spec_version_for_transport() -> str:
    return os.getenv("MCP_SPEC_SCHEMA_VERSION", "2025-11-25")


def _uses_streamable_http(version: str) -> bool:
    try:
        return date.fromisoformat(version) >= date.fromisoformat(
            STREAMABLE_HTTP_PROTOCOL_VERSION
        )
    except ValueError:
        return False


def _resolve_protocol_for_spec(protocol: str) -> str:
    normalized = protocol.strip().lower()
    if normalized not in ("http", "https"):
        return normalized
    if _uses_streamable_http(_spec_version_for_transport()):
        return "streamablehttp"
    return normalized


def build_driver_with_auth(request: TransportBuildRequest):
    """Create a transport with authentication headers when available."""
    resolved_protocol = _resolve_protocol_for_spec(request.protocol)
    resolved = TransportBuildRequest(
        protocol=resolved_protocol,
        endpoint=request.endpoint,
        timeout=request.timeout,
        transport_retries=request.transport_retries,
        transport_retry_delay=request.transport_retry_delay,
        transport_retry_backoff=request.transport_retry_backoff,
        transport_retry_max_delay=request.transport_retry_max_delay,
        transport_retry_jitter=request.transport_retry_jitter,
        auth_manager=request.auth_manager,
        safety_enabled=request.safety_enabled,
    )
    try:
        auth_header_provider = None
        auth_manager = resolved.auth_manager

        if auth_manager:

            def auth_header_provider() -> dict[str, str]:
                auth_headers = auth_manager.get_default_auth_headers()
                if not auth_headers:
                    auth_headers = auth_manager.get_auth_headers_for_tool(
                        ""
                    )  # pragma: no cover
                return auth_headers

            logger.debug("Auth manager found for transport")

        factory_kwargs = {"timeout": resolved.timeout}
        safety_enabled = resolved.safety_enabled

        if resolved.protocol in AUTH_PROTOCOLS:
            factory_kwargs["safety_enabled"] = safety_enabled
        if resolved.protocol in AUTH_PROTOCOLS and auth_header_provider:
            factory_kwargs["auth_header_provider"] = auth_header_provider
            logger.debug(
                "Adding auth provider to %s transport", resolved.protocol.upper()
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


__all__ = [
    "AUTH_PROTOCOLS",
    "TransportBuildRequest",
    "build_driver_with_auth",
]
