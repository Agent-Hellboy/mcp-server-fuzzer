#!/usr/bin/env python3
"""Application composition root: wire bootstrap, orchestrator, and post-run."""

from __future__ import annotations

import logging
import os

from ..exceptions import MCPError
from ..orchestrator import run_session
from .bootstrap import SessionBootstrap
from .post_run import PostRunPresenter
from .session_settings import SessionSettings


def _warn_if_spec_schema_unavailable(requested: str) -> None:
    """Warn when spec validation was requested but no schema can back it.

    The MCP schemas live in the ``schemas/mcp-spec`` git submodule, which is
    absent from an installed package. Without it every spec check silently
    passes, so an assessor would believe they validated against a spec
    version that was never loaded.
    """
    try:
        from ..spec_guard.spec_version import supported_protocol_versions

        available = supported_protocol_versions()
    except Exception as exc:  # pragma: no cover - defensive
        logging.warning("Could not determine supported spec versions: %s", exc)
        return

    if not available:
        logging.warning(
            "Spec schema version %s was requested but no MCP schemas are "
            "available, so spec validation will not run. Set "
            "MCP_SPEC_SCHEMA_ROOT to a checkout of the MCP schema directory, "
            "or run from a repository with the schemas/mcp-spec submodule "
            "initialised.",
            requested,
        )
    elif requested not in available:
        logging.warning(
            "Spec schema version %s is not among the available versions (%s); "
            "spec validation for it will not run.",
            requested,
            ", ".join(available),
        )


async def run_fuzz_app(settings: SessionSettings) -> int:
    """Run the fuzzing workflow using merged session settings."""
    config = settings.config

    if settings.spec_schema_version is not None:
        os.environ["MCP_SPEC_SCHEMA_VERSION"] = str(
            settings.spec_schema_version
        )
        _warn_if_spec_schema_unavailable(str(settings.spec_schema_version))

    try:
        from ..runtime_probe import PROBE

        PROBE.configure_from_mapping(config)
    except Exception as exc:
        logging.warning("runtime probe configuration failed: %s", exc)

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

        return await PostRunPresenter(settings, bundle.reporter).present(result)
    except MCPError:
        raise
    except Exception as exc:
        logging.error("Error during fuzzing: %s", exc)
        return 1
    finally:
        await bundle.client.cleanup()


__all__ = ["run_fuzz_app"]
