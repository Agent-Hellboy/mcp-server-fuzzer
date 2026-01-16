#!/usr/bin/env python3
"""Transport factory that layers auth resolution on top of the base registry."""

from __future__ import annotations

import logging
import sys
from typing import Any

from rich.console import Console

from ...transport.catalog import build_driver as base_build_driver

logger = logging.getLogger(__name__)
AUTH_PROTOCOLS = ("http", "https", "streamablehttp", "sse")


def build_driver_with_auth(args: Any, client_args: dict[str, Any]):
    """Create a transport with authentication headers when available."""
    try:
        auth_headers = None
        auth_manager = client_args.get("auth_manager")

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

        factory_kwargs = {"timeout": args.timeout}
        safety_enabled = client_args.get("safety_enabled", True)

        if args.protocol in AUTH_PROTOCOLS:
            factory_kwargs["safety_enabled"] = safety_enabled
        if args.protocol in AUTH_PROTOCOLS and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers
            logger.debug("Adding auth headers to %s transport", args.protocol.upper())

        logger.debug(
            "Creating %s transport to %s",
            args.protocol.upper(),
            args.endpoint,
        )
        transport = base_build_driver(
            args.protocol,
            args.endpoint,
            **factory_kwargs,
        )
        return transport
    except Exception as transport_error:  # pragma: no cover
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
        logger.exception("Transport creation failed")
        sys.exit(1)


__all__ = ["build_driver_with_auth"]
