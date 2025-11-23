#!/usr/bin/env python3
"""Transport factory that layers auth resolution on top of the base registry."""

from __future__ import annotations

import logging
import sys
from typing import Any

from rich.console import Console

from ...transport.factory import create_transport as base_create_transport

logger = logging.getLogger(__name__)


def create_transport_with_auth(args: Any, client_args: dict[str, Any]):
    """Create a transport with authentication headers when available."""
    try:
        auth_headers = None
        auth_manager = client_args.get("auth_manager")

        if auth_manager:
            auth_headers = auth_manager.get_default_auth_headers()
            if not auth_headers:
                auth_headers = auth_manager.get_auth_headers_for_tool("")  # pragma: no cover
            if auth_headers:
                logger.debug(f"Auth headers found for transport: {list(auth_headers.keys())}")
            else:
                logger.debug("No auth headers found for default tool mapping")  # pragma: no cover

        factory_kwargs = {"timeout": args.timeout}

        if args.protocol in ("http", "https", "streamablehttp", "sse") and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers
            logger.debug(f"Adding auth headers to {args.protocol.upper()} transport")

        logger.debug(f"Creating {args.protocol.upper()} transport to {args.endpoint}")
        transport = base_create_transport(
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


__all__ = ["create_transport_with_auth"]
