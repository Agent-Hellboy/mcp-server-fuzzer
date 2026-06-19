#!/usr/bin/env python3
"""Transport bootstrap that layers auth resolution on top of the base registry."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Callable

from ..exceptions import TransportRegistrationError
from ..transport.catalog import build_driver as base_build_driver
from ..transport.protocol import current_protocol_version, supports_streamable_http
from ..transport.retrying import RetryingTransport, RetryPolicy
from ..types import AuthManagerProtocol

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


def _resolve_protocol_for_spec(protocol: str) -> str:
    normalized = protocol.strip().lower()
    if normalized not in ("http", "https"):
        return normalized
    if supports_streamable_http(current_protocol_version()):
        return "streamablehttp"
    return normalized


def _seed_streamable_protocol_version(transport, protocol: str) -> None:
    if protocol == "streamablehttp" and hasattr(transport, "protocol_version"):
        transport.protocol_version = current_protocol_version()


def _auth_header_provider(
    auth_manager: AuthManagerProtocol | None,
) -> Callable[[], dict[str, str]] | None:
    if auth_manager is None:
        return None

    def provider() -> dict[str, str]:
        auth_headers = auth_manager.get_default_auth_headers()
        if not auth_headers:
            auth_headers = auth_manager.get_auth_headers_for_tool(
                ""
            )  # pragma: no cover
        return auth_headers

    logger.debug("Auth manager found for transport")
    return provider


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
        auth_header_provider = _auth_header_provider(resolved.auth_manager)
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
        _seed_streamable_protocol_version(transport, resolved.protocol)
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
