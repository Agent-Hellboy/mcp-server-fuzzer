#!/usr/bin/env python3
"""
MCP Fuzzer Client Package

This package provides a modular client for fuzzing MCP servers.
"""

import logging
from typing import List, Optional

import emoji

from ..transport import create_transport
from ..reports import FuzzerReporter
from .base import MCPFuzzerClient

# For backward compatibility
UnifiedMCPFuzzerClient = MCPFuzzerClient


async def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI application.

    Args:
        argv: Command line arguments (optional)

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from ..cli.args import get_cli_config

    # Get configuration from CLI args, env vars, and config files
    config = get_cli_config()

    # Also get the global config which has all the export flags
    from ..config import config as global_config
    logging.info(f"Global config object: {global_config}")
    logging.info(f"Global config dict: {global_config._config}")
    logging.info(
        f"Client received config with export flags: "
        f"csv={global_config.get('export_csv')}, "
        f"xml={global_config.get('export_xml')}, "
        f"html={global_config.get('export_html')}, "
        f"md={global_config.get('export_markdown')}"
    )

    # Create transport based on configuration
    transport = create_transport(
        config["protocol"],
        config["endpoint"],
        timeout=config.get("timeout"),
    )

    # Create reporter with custom output directory if specified
    reporter = None
    if "output_dir" in config:
        reporter = FuzzerReporter(output_dir=config["output_dir"])

    # Create client
    client = MCPFuzzerClient(
        transport=transport,
        auth_manager=config.get("auth_manager"),
        tool_timeout=config.get("tool_timeout"),
        reporter=reporter,
        max_concurrency=config.get("max_concurrency", 5),
    )

    try:
        # Execute fuzzing based on mode
        tool_results = {}
        if config["mode"] == "tools":
            if config.get("phase") == "both":
                tool_results = await client.fuzz_all_tools_both_phases(
                    runs_per_phase=config.get("runs", 10)
                )
            else:
                tool_results = await client.fuzz_all_tools(
                    runs_per_tool=config.get("runs", 10)
                )
        elif config["mode"] == "tool":
            if config.get("phase") == "both":
                tool_results = await client.fuzz_tool_both_phases(
                    config["tool"], runs_per_phase=config.get("runs", 10)
                )
            else:
                tool_results = await client.fuzz_tool(
                    config["tool"], runs=config.get("runs", 10)
                )
        elif config["mode"] == "protocol":
            if config.get("protocol_type"):
                await client.fuzz_protocol_type(
                    config["protocol_type"], runs=config.get("runs_per_type", 10)
                )
            else:
                await client.fuzz_all_protocol_types(
                    runs_per_type=config.get("runs_per_type", 10)
                )
        elif config["mode"] == "both":
            # Run both tools and protocol fuzzing
            logging.info("Running both tools and protocol fuzzing")

            # First, fuzz tools
            if config.get("phase") == "both":
                tool_results = await client.fuzz_all_tools_both_phases(
                    runs_per_phase=config.get("runs", 10)
                )
            else:
                tool_results = await client.fuzz_all_tools(
                    runs_per_tool=config.get("runs", 10)
                )

            # Then, fuzz protocol types
            if config.get("protocol_type"):
                await client.fuzz_protocol_type(
                    config["protocol_type"], runs=config.get("runs_per_type", 10)
                )
            else:
                await client.fuzz_all_protocol_types(
                    runs_per_type=config.get("runs_per_type", 10)
                )
        else:
            logging.error(f"Unknown mode: {config['mode']}")
            return 1

        # Display Rich table summary
        try:
            if (config["mode"] == "tools" or config["mode"] == "tool") and tool_results:
                print("\n" + "="*80)
                print(f"{emoji.emojize(':bullseye:')} MCP FUZZER TOOL RESULTS SUMMARY")
                print("="*80)
                client.print_tool_summary(tool_results)

                # Calculate and display overall stats
                total_tools = len(tool_results)
                total_runs = sum(len(runs) for runs in tool_results.values())
                total_exceptions = sum(
                    len([r for r in runs if r.get('exception')])
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

                # Show vulnerabilities
                vulnerable_tools = []
                for tool_name, runs in tool_results.items():
                    exceptions = len([r for r in runs if r.get('exception')])
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

        except Exception as e:
            logging.warning(f"Failed to display table summary: {e}")

        # Generate standardized reports
        try:
            output_types = config.get("output_types")
            standardized_files = client.generate_standardized_reports(
                output_types=output_types,
                include_safety=config.get("safety_report", False)
            )
            if standardized_files:
                logging.info(
                    f"Generated standardized reports: {list(standardized_files.keys())}"
                )
        except Exception as e:
            logging.warning(f"Failed to generate standardized reports: {e}")

        # Export results to additional formats if requested
        try:
            logging.info(
                f"Checking export flags: csv={global_config.get('export_csv')}, "
                f"xml={global_config.get('export_xml')}, "
                f"html={global_config.get('export_html')}, "
                f"md={global_config.get('export_markdown')}"
            )
            logging.info(f"Client reporter available: {client.reporter is not None}")

            if global_config.get("export_csv"):
                csv_filename = global_config["export_csv"]
                if client.reporter:
                    client.reporter.export_csv(csv_filename)
                    logging.info(f"Exported CSV report to: {csv_filename}")
                else:
                    logging.warning("No reporter available for CSV export")

            if global_config.get("export_xml"):
                xml_filename = global_config["export_xml"]
                if client.reporter:
                    client.reporter.export_xml(xml_filename)
                    logging.info(f"Exported XML report to: {xml_filename}")
                else:
                    logging.warning("No reporter available for XML export")

            if global_config.get("export_html"):
                html_filename = global_config["export_html"]
                if client.reporter:
                    client.reporter.export_html(html_filename)
                    logging.info(f"Exported HTML report to: {html_filename}")
                else:
                    logging.warning("No reporter available for HTML export")

            if global_config.get("export_markdown"):
                markdown_filename = global_config["export_markdown"]
                if client.reporter:
                    client.reporter.export_markdown(markdown_filename)
                    logging.info(f"Exported Markdown report to: {markdown_filename}")
                else:
                    logging.warning("No reporter available for Markdown export")

        except Exception as e:
            logging.warning(f"Failed to export additional report formats: {e}")
            logging.exception("Export error details:")

        return 0
    except Exception as e:
        logging.error(f"Error during fuzzing: {e}")
        return 1
    finally:
        # Ensure proper shutdown
        await client.cleanup()


__all__ = ["MCPFuzzerClient", "UnifiedMCPFuzzerClient", "main"]
