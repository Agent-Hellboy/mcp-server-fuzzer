#!/usr/bin/env python3
"""Unified client entrypoint used by the CLI runtime."""

from __future__ import annotations

import logging
import os

import emoji

from ..reports import FuzzerReporter
from ..reports.formatters.common import extract_tool_runs
from ..safety_system.safety import SafetyFilter
from ..exceptions import MCPError
from ..corpus import build_corpus_root, build_target_id, default_fs_root
from .settings import ClientSettings
from .base import MCPFuzzerClient
from .transport import build_driver_with_auth
from .runtime import RunContext, build_run_plan

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

    class Args:
        def __init__(
            self,
            protocol,
            endpoint,
            timeout,
            transport_retries,
            transport_retry_delay,
            transport_retry_backoff,
            transport_retry_max_delay,
            transport_retry_jitter,
        ):
            self.protocol = protocol
            self.endpoint = endpoint
            self.timeout = timeout
            self.transport_retries = transport_retries
            self.transport_retry_delay = transport_retry_delay
            self.transport_retry_backoff = transport_retry_backoff
            self.transport_retry_max_delay = transport_retry_max_delay
            self.transport_retry_jitter = transport_retry_jitter

    args = Args(
        protocol=config["protocol"],
        endpoint=config["endpoint"],
        timeout=config.get("timeout", 30.0),
        transport_retries=config.get("transport_retries", 1),
        transport_retry_delay=config.get("transport_retry_delay", 0.5),
        transport_retry_backoff=config.get("transport_retry_backoff", 2.0),
        transport_retry_max_delay=config.get("transport_retry_max_delay", 5.0),
        transport_retry_jitter=config.get("transport_retry_jitter", 0.1),
    )  # pragma: no cover

    client_args = {
        "auth_manager": config.get("auth_manager"),
    }

    transport = build_driver_with_auth(args, client_args)

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
                print("\n" + "=" * 80)
                print(f"{emoji.emojize(':bullseye:')} MCP FUZZER TOOL RESULTS SUMMARY")
                print("=" * 80)
                client.print_tool_summary(tool_results)

                total_tools = len(tool_results)
                total_runs = sum(
                    len(extract_tool_runs(runs)[0]) for runs in tool_results.values()
                )
                total_exceptions = sum(
                    len([r for r in extract_tool_runs(runs)[0] if r.get("exception")])
                    for runs in tool_results.values()
                )

                success_rate = (
                    ((total_runs - total_exceptions) / total_runs * 100)
                    if total_runs > 0
                    else 0
                )

                print(f"\n{emoji.emojize(':chart_increasing:')} OVERALL STATISTICS")
                print("-" * 40)
                print(f"• Total Tools Tested: {total_tools}")
                print(f"• Total Fuzzing Runs: {total_runs}")
                print(f"• Total Exceptions: {total_exceptions}")
                print(f"• Overall Success Rate: {success_rate:.1f}%")

                vulnerable_tools = []
                for tool_name, runs in tool_results.items():
                    run_entries = extract_tool_runs(runs)[0]
                    exceptions = len([r for r in run_entries if r.get("exception")])
                    if exceptions > 0:
                        vulnerable_tools.append(
                            (tool_name, exceptions, len(run_entries))
                        )

                if vulnerable_tools:
                    print(
                        f"\n{emoji.emojize(':police_car_light:')} "
                        f"VULNERABILITIES FOUND: {len(vulnerable_tools)}"
                    )
                    for tool, exceptions, total in vulnerable_tools:
                        rate = exceptions / total * 100
                        print(
                            f"  • {tool}: {exceptions}/{total} exceptions ({rate:.1f}%)"
                        )
                else:
                    print(
                        f"\n{emoji.emojize(':check_mark_button:')} "
                        f"NO VULNERABILITIES FOUND"
                    )

        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display table summary: {exc}")

        try:  # pragma: no cover
            if isinstance(protocol_results, dict) and protocol_results:
                print("\n" + "=" * 80)
                print(
                    f"{emoji.emojize(':rocket:')} MCP FUZZER PROTOCOL RESULTS SUMMARY"
                )
                print("=" * 80)
                client.print_protocol_summary(protocol_results)
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display protocol summary tables: {exc}")

        try:  # pragma: no cover
            output_types = config.get("output_types")
            standardized_files = await client.generate_standardized_reports(
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
            logging.info(
                "Checking export flags: "
                f"csv={config.get('export_csv', False)}, "
                f"xml={config.get('export_xml', False)}, "
                f"html={config.get('export_html', False)}, "
                f"md={config.get('export_markdown', False)}"
            )
            logging.info(f"Client reporter available: {client.reporter is not None}")

            if config.get("export_csv"):
                csv_filename = config["export_csv"]
                if client.reporter:
                    await client.reporter.export_format("csv", csv_filename)
                    logging.info(f"Exported CSV report to: {csv_filename}")
                else:
                    logging.warning("No reporter available for CSV export")

            if config.get("export_xml"):
                xml_filename = config["export_xml"]
                if client.reporter:
                    await client.reporter.export_format("xml", xml_filename)
                    logging.info(f"Exported XML report to: {xml_filename}")
                else:
                    logging.warning("No reporter available for XML export")

            if config.get("export_html"):
                html_filename = config["export_html"]
                if client.reporter:
                    await client.reporter.export_format("html", html_filename)
                    logging.info(f"Exported HTML report to: {html_filename}")
                else:
                    logging.warning("No reporter available for HTML export")

            if config.get("export_markdown"):
                markdown_filename = config["export_markdown"]
                if client.reporter:
                    await client.reporter.export_format("markdown", markdown_filename)
                    logging.info(f"Exported Markdown report to: {markdown_filename}")
                else:
                    logging.warning("No reporter available for Markdown export")

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
