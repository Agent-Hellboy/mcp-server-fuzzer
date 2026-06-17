#!/usr/bin/env python3
"""Application composition root: wire bootstrap, orchestrator, and post-run."""

from __future__ import annotations

import logging
import os

from ..exceptions import MCPError
from ..orchestrator import run_session
from ..client.settings import ClientSettings
from .bootstrap import SessionBootstrap
from .post_run import PostRunPresenter
from .session_settings import SessionSettings


async def run_fuzz_app(settings: ClientSettings) -> int:
    """Run the fuzzing workflow using merged client settings."""
    session_settings = SessionSettings(settings.data)
    config = session_settings.config

    if session_settings.spec_schema_version is not None:
        os.environ["MCP_SPEC_SCHEMA_VERSION"] = str(
            session_settings.spec_schema_version
        )

    logging.info(  # pragma: no cover
        "Client received config with export flags: "
        f"csv={config.get('export_csv', False)}, "
        f"xml={config.get('export_xml', False)}, "
        f"html={config.get('export_html', False)}, "
        f"md={config.get('export_markdown', False)}"
    )

    bundle = SessionBootstrap(settings).build()

    try:
        try:
            result = await run_session(
                bundle.context,
                transport=bundle.transport,
                build_transport_request=bundle.build_transport_request,
            )
        except ValueError as exc:
            logging.error("Failed to build run plan: %s", exc)
            return 1

        return await PostRunPresenter(session_settings, bundle.reporter).present(result)
    except MCPError:
        raise
    except Exception as exc:
        logging.error("Error during fuzzing: %s", exc)
        return 1
    finally:
        await bundle.client.cleanup()


__all__ = ["run_fuzz_app"]
