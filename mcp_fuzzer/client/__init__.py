#!/usr/bin/env python3
"""
MCP Fuzzer Client Package

This package provides a modular client for fuzzing MCP servers.
"""

import logging
from typing import Any

from .base import MCPFuzzerClient
from .builder import ClientFactory
from .orchestrator import ClientOrchestrator

# For backward compatibility
UnifiedMCPFuzzerClient = MCPFuzzerClient

async def main(argv: list[str] | None = None) -> int:
    """Main entry point for the CLI application.

    Args:
        argv: Command line arguments (optional)

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from ..cli.args import get_cli_config

    # Get configuration from CLI args, env vars, and config files
    config = get_cli_config()

    # Log export flags using local config
    logging.info(
        f"Client received config with export flags: "
        f"csv={config.get('export_csv', False)}, "
        f"xml={config.get('export_xml', False)}, "
        f"html={config.get('export_html', False)}, "
        f"md={config.get('export_markdown', False)}"
    )

    # Create client using factory (clean dependency injection)
    client = ClientFactory.create_from_config(config)

    # Create orchestrator for execution
    orchestrator = ClientOrchestrator(client)

    try:
        # Execute fuzzing using strategy pattern
        exit_code = await orchestrator.execute_with_error_handling(config)
        if exit_code != 0:
            return exit_code

        # Handle reporting and display logic
        await _handle_post_execution_reporting(client, config)

        return 0
    except Exception as e:
        logging.error(f"Error during fuzzing: {e}")
        return 1
    finally:
        # Ensure proper shutdown
        await client.cleanup()


async def _handle_post_execution_reporting(
    client: MCPFuzzerClient, config: dict[str, Any]
) -> None:
    """Handle post-execution reporting and display logic."""
    try:
        # Generate standardized reports
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
            f"Checking export flags: csv={config.get('export_csv', False)}, "
            f"xml={config.get('export_xml', False)}, "
            f"html={config.get('export_html', False)}, "
            f"md={config.get('export_markdown', False)}"
        )
        logging.info(f"Client reporter available: {client.reporter is not None}")

        if config.get("export_csv"):
            csv_filename = config["export_csv"]
            if client.reporter:
                client.reporter.export_csv(csv_filename)
                logging.info(f"Exported CSV report to: {csv_filename}")
            else:
                logging.warning("No reporter available for CSV export")

        if config.get("export_xml"):
            xml_filename = config["export_xml"]
            if client.reporter:
                client.reporter.export_xml(xml_filename)
                logging.info(f"Exported XML report to: {xml_filename}")
            else:
                logging.warning("No reporter available for XML export")

        if config.get("export_html"):
            html_filename = config["export_html"]
            if client.reporter:
                client.reporter.export_html(html_filename)
                logging.info(f"Exported HTML report to: {html_filename}")
            else:
                logging.warning("No reporter available for HTML export")

        if config.get("export_markdown"):
            markdown_filename = config["export_markdown"]
            if client.reporter:
                client.reporter.export_markdown(markdown_filename)
                logging.info(f"Exported Markdown report to: {markdown_filename}")
            else:
                logging.warning("No reporter available for Markdown export")

    except Exception as e:
        logging.warning(f"Failed to export additional report formats: {e}")
        logging.exception("Export error details:")

__all__ = ["MCPFuzzerClient", "UnifiedMCPFuzzerClient", "main"]
