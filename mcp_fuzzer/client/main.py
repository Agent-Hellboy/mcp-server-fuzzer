#!/usr/bin/env python3
"""Unified client entrypoint used by the CLI runtime."""

from __future__ import annotations

import logging
from typing import Any

import emoji

from ..reports import FuzzerReporter
from ..safety_system.safety import SafetyFilter
from ..exceptions import MCPError
from .settings import ClientSettings
from .base import MCPFuzzerClient
from .transport import build_driver_with_auth

# For backward compatibility
UnifiedMCPFuzzerClient = MCPFuzzerClient


async def unified_client_main(settings: ClientSettings) -> int:
    """Run the fuzzing workflow using merged client settings."""
    config = settings.data

    logging.info(  # pragma: no cover
        "Client received config with export flags: "
        f"csv={config.get('export_csv', False)}, "
        f"xml={config.get('export_xml', False)}, "
        f"html={config.get('export_html', False)}, "
        f"md={config.get('export_markdown', False)}"
    )

    class Args:
        def __init__(self, protocol, endpoint, timeout):
            self.protocol = protocol
            self.endpoint = endpoint
            self.timeout = timeout

    args = Args(
        protocol=config["protocol"],
        endpoint=config["endpoint"],
        timeout=config.get("timeout", 30.0),
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

    client = MCPFuzzerClient(
        transport=transport,
        auth_manager=config.get("auth_manager"),
        tool_timeout=config.get("tool_timeout"),
        reporter=reporter,
        safety_system=safety_system,
        safety_enabled=safety_enabled,
        max_concurrency=config.get("max_concurrency", 5),
    )

    try:
        tool_results: dict[str, Any] = {}
        protocol_results: dict[str, Any] = {}
        mode = config["mode"]
        if mode == "tools":
            if config.get("phase") == "both":
                if config.get("tool"):
                    tool_results = await client.fuzz_tool_both_phases(
                        config["tool"], runs_per_phase=config.get("runs", 10)
                    )
                else:
                    tool_results = await client.fuzz_all_tools_both_phases(
                        runs_per_phase=config.get("runs", 10)
                    )
            else:
                if config.get("tool"):
                    tool_results = await client.fuzz_tool(
                        config["tool"], runs=config.get("runs", 10)
                    )
                else:
                    tool_results = await client.fuzz_all_tools(
                        runs_per_tool=config.get("runs", 10)
                    )
        elif mode == "protocol":
            if config.get("spec_guard", True):
                checks = await client.run_spec_suite(
                    resource_uri=config.get("spec_resource_uri"),
                    prompt_name=config.get("spec_prompt_name"),
                    prompt_args=config.get("spec_prompt_args"),
                )
                failed = [
                    c for c in checks if str(c.get("status", "")).upper() == "FAIL"
                ]
                logging.info(
                    "Spec guard checks completed: %d total, %d failed",
                    len(checks),
                    len(failed),
                )
            if config.get("protocol_type"):
                protocol_type = config["protocol_type"]
                protocol_results[protocol_type] = await client.fuzz_protocol_type(
                    protocol_type,
                    runs=config.get("runs_per_type", 10),
                )
            else:
                protocol_results = await client.fuzz_all_protocol_types(
                    runs_per_type=config.get("runs_per_type", 10)
                )
        elif mode == "resources":
            if config.get("spec_guard", True):
                checks = await client.run_spec_suite(
                    resource_uri=config.get("spec_resource_uri"),
                    prompt_name=config.get("spec_prompt_name"),
                    prompt_args=config.get("spec_prompt_args"),
                )
                failed = [
                    c for c in checks if str(c.get("status", "")).upper() == "FAIL"
                ]
                logging.info(
                    "Spec guard checks completed: %d total, %d failed",
                    len(checks),
                    len(failed),
                )
            protocol_results = await client.fuzz_resources(
                runs_per_type=config.get("runs_per_type", 10)
            )
        elif mode == "prompts":
            if config.get("spec_guard", True):
                checks = await client.run_spec_suite(
                    resource_uri=config.get("spec_resource_uri"),
                    prompt_name=config.get("spec_prompt_name"),
                    prompt_args=config.get("spec_prompt_args"),
                )
                failed = [
                    c for c in checks if str(c.get("status", "")).upper() == "FAIL"
                ]
                logging.info(
                    "Spec guard checks completed: %d total, %d failed",
                    len(checks),
                    len(failed),
                )
            protocol_results = await client.fuzz_prompts(
                runs_per_type=config.get("runs_per_type", 10)
            )
        elif mode == "all":
            logging.info("Running both tools and protocol fuzzing")  # pragma: no cover
            if config.get("phase") == "both":
                if config.get("tool"):
                    tool_results = await client.fuzz_tool_both_phases(
                        config["tool"], runs_per_phase=config.get("runs", 10)
                    )
                else:
                    tool_results = await client.fuzz_all_tools_both_phases(
                        runs_per_phase=config.get("runs", 10)
                    )
            else:
                if config.get("tool"):
                    tool_results = await client.fuzz_tool(
                        config["tool"], runs=config.get("runs", 10)
                    )
                else:
                    tool_results = await client.fuzz_all_tools(
                        runs_per_tool=config.get("runs", 10)
                    )
            if config.get("spec_guard", True):
                checks = await client.run_spec_suite(
                    resource_uri=config.get("spec_resource_uri"),
                    prompt_name=config.get("spec_prompt_name"),
                    prompt_args=config.get("spec_prompt_args"),
                )
                failed = [
                    c for c in checks if str(c.get("status", "")).upper() == "FAIL"
                ]
                logging.info(
                    "Spec guard checks completed: %d total, %d failed",
                    len(checks),
                    len(failed),
                )
            if config.get("protocol_type"):
                protocol_type = config["protocol_type"]
                protocol_results[protocol_type] = await client.fuzz_protocol_type(
                    protocol_type,
                    runs=config.get("runs_per_type", 10),
                )
            else:
                protocol_results = await client.fuzz_all_protocol_types(
                    runs_per_type=config.get("runs_per_type", 10)
                )
        else:
            logging.error(f"Unknown mode: {config['mode']}")
            return 1

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
                total_runs = sum(len(runs) for runs in tool_results.values())
                total_exceptions = sum(
                    len([r for r in runs if r.get("exception")])
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
                    exceptions = len([r for r in runs if r.get("exception")])
                    if exceptions > 0:
                        vulnerable_tools.append((tool_name, exceptions, len(runs)))

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

        if isinstance(protocol_results, dict) and protocol_results:
            for protocol_type, results in protocol_results.items():
                client.reporter.add_protocol_results(protocol_type, results)

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
                    await client.reporter.export_csv(csv_filename)
                    logging.info(f"Exported CSV report to: {csv_filename}")
                else:
                    logging.warning("No reporter available for CSV export")

            if config.get("export_xml"):
                xml_filename = config["export_xml"]
                if client.reporter:
                    await client.reporter.export_xml(xml_filename)
                    logging.info(f"Exported XML report to: {xml_filename}")
                else:
                    logging.warning("No reporter available for XML export")

            if config.get("export_html"):
                html_filename = config["export_html"]
                if client.reporter:
                    await client.reporter.export_html(html_filename)
                    logging.info(f"Exported HTML report to: {html_filename}")
                else:
                    logging.warning("No reporter available for HTML export")

            if config.get("export_markdown"):
                markdown_filename = config["export_markdown"]
                if client.reporter:
                    await client.reporter.export_markdown(markdown_filename)
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


__all__ = ["unified_client_main", "UnifiedMCPFuzzerClient", "MCPFuzzerClient"]
