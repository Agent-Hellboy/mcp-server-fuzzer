#!/usr/bin/env python3
"""Unified client entrypoint used by the CLI runtime."""

from __future__ import annotations

import logging
import os
from typing import Any

from ..reports import FuzzerReporter
from ..safety_system.safety import SafetyFilter
from ..exceptions import MCPError
from ..corpus import build_corpus_root, build_target_id, default_fs_root
from .settings import ClientSettings
from .base import MCPFuzzerClient
from .transport import TransportBuildRequest, build_driver_with_auth
from .runtime import RunContext, build_run_plan


def _build_transport_request(config: dict[str, Any]) -> TransportBuildRequest:
    return TransportBuildRequest(
        protocol=config["protocol"],
        endpoint=config["endpoint"],
        timeout=config.get("timeout", 30.0),
        transport_retries=config.get("transport_retries", 1),
        transport_retry_delay=config.get("transport_retry_delay", 0.5),
        transport_retry_backoff=config.get("transport_retry_backoff", 2.0),
        transport_retry_max_delay=config.get("transport_retry_max_delay", 5.0),
        transport_retry_jitter=config.get("transport_retry_jitter", 0.1),
        auth_manager=config.get("auth_manager"),
        safety_enabled=config.get("safety_enabled", True),
    )


def _requested_export_targets(config: dict[str, Any]) -> dict[str, str]:
    export_targets: dict[str, str] = {}
    for config_key, format_name in (
        ("export_csv", "csv"),
        ("export_xml", "xml"),
        ("export_html", "html"),
        ("export_markdown", "markdown"),
    ):
        filename = config.get(config_key)
        if filename:
            export_targets[format_name] = filename
    return export_targets


def _set_report_metadata(reporter: FuzzerReporter, config: dict[str, Any]) -> None:
    reporter.set_fuzzing_metadata(
        mode=config.get("mode", "unknown"),
        protocol=config.get("protocol", "unknown"),
        endpoint=config.get("endpoint", "unknown"),
        runs=config.get("runs", 0),
        runs_per_type=config.get("runs_per_type"),
    )


async def unified_client_main(settings: ClientSettings) -> int:
    """Run the fuzzing workflow using merged client settings."""
    config = settings.data

    schema_version = config.get("spec_schema_version")
    if schema_version is not None:
        os.environ["MCP_SPEC_SCHEMA_VERSION"] = str(schema_version)

    logging.info(  # pragma: no cover
        "Client received config with export flags: "
        f"csv={config.get('export_csv', False)}, "
        f"xml={config.get('export_xml', False)}, "
        f"html={config.get('export_html', False)}, "
        f"md={config.get('export_markdown', False)}"
    )

    transport = build_driver_with_auth(_build_transport_request(config))

    safety_enabled = config.get("safety_enabled", True)
    safety_system = None
    if safety_enabled:
        safety_system = SafetyFilter()
        fs_root = config.get("fs_root")
        if fs_root:
            try:
                safety_system.set_fs_root(fs_root)
            except Exception as exc:  # pragma: no cover
                logging.warning(f"Failed to set filesystem root '{fs_root}': {exc}")

    reporter = None
    if "output_dir" in config:
        reporter = FuzzerReporter(
            output_dir=config["output_dir"], safety_system=safety_system
        )

    corpus_root = None
    if config.get("corpus_enabled", True):
        endpoint = config.get("endpoint") or "unknown"
        protocol = config.get("protocol", "unknown")
        target_id = build_target_id(protocol, endpoint)
        fs_root = config.get("fs_root") or str(default_fs_root())
        corpus_root = str(build_corpus_root(fs_root, target_id))

    client = MCPFuzzerClient(
        transport=transport,
        auth_manager=config.get("auth_manager"),
        tool_timeout=config.get("tool_timeout"),
        reporter=reporter,
        safety_system=safety_system,
        safety_enabled=safety_enabled,
        max_concurrency=config.get("max_concurrency", 5),
        corpus_root=corpus_root,
        havoc_mode=config.get("havoc_mode", False),
    )
    reporter = client.reporter
    _set_report_metadata(reporter, config)

    try:
        mode = config["mode"]
        protocol_phase = config.get("protocol_phase", "realistic")
        context = RunContext(
            client=client,
            config=config,
            reporter=reporter,
            protocol_phase=protocol_phase,
        )
        try:
            plan = build_run_plan(mode, config)
        except ValueError as exc:
            logging.error("Failed to build run plan: %s", exc)
            return 1
        await plan.execute(context)
        tool_results = context.tool_results
        protocol_results = context.protocol_results

        try:  # pragma: no cover
            if (
                mode in ["tools", "all"]
                and isinstance(tool_results, dict)
                and tool_results
            ):
                reporter.print_tool_execution_summary(tool_results)

        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display table summary: {exc}")

        try:  # pragma: no cover
            if isinstance(protocol_results, dict) and protocol_results:
                reporter.print_protocol_summary(protocol_results)
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display protocol summary tables: {exc}")

        try:  # pragma: no cover
            output_types = config.get("output_types")
            standardized_files = await reporter.generate_standardized_report(
                output_types=output_types,
                include_safety=config.get("safety_report", False),
            )
            if standardized_files:
                logging.info(
                    f"Generated standardized reports: {list(standardized_files.keys())}"
                )
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to generate standardized reports: {exc}")

        try:  # pragma: no cover
            export_targets = _requested_export_targets(config)
            exported_files = await reporter.export_requested_formats(
                export_targets,
                include_safety=config.get("safety_report", False),
            )
            if exported_files:
                logging.info(
                    "Exported report formats: %s",
                    {name: path for name, path in exported_files.items()},
                )

        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to export additional report formats: {exc}")
            logging.exception("Export error details:")

        return 0
    except MCPError:
        raise
    except Exception as exc:
        logging.error(f"Error during fuzzing: {exc}")
        return 1
    finally:
        await client.cleanup()


__all__ = ["unified_client_main", "MCPFuzzerClient"]
