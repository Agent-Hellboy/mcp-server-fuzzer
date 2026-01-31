#!/usr/bin/env python3
"""Argument parser for the MCP fuzzer CLI."""

from __future__ import annotations

import argparse


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MCP Fuzzer - Comprehensive fuzzing for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            """
Examples:
  # Fuzz tools only
  mcp-fuzzer --mode tools --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs 10

  # Fuzz protocol types only
  mcp-fuzzer --mode protocol --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs-per-type 5

  # Fuzz tools + protocol (default)
  mcp-fuzzer --mode all --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs 10 --runs-per-type 5

  # Fuzz specific protocol type
  mcp-fuzzer --mode protocol --protocol-type InitializeRequest \
    --protocol http --endpoint http://localhost:8000/mcp/

  # Fuzz a single tool
  mcp-fuzzer --mode tools --tool analyze_repository --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs 10

  # Fuzz with verbose output
  mcp-fuzzer --mode all --protocol http \
    --endpoint http://localhost:8000/mcp/ --verbose
            """
        ),
    )

    # Configuration file options
    parser.add_argument(
        "--config",
        "-c",
        help="Path to configuration file (YAML: .yml or .yaml)",
        default=None,
    )

    parser.add_argument(
        "--mode",
        choices=["tools", "protocol", "resources", "prompts", "all"],
        default="all",
        help=(
            "Fuzzing mode: 'tools' for tool fuzzing (optionally --tool), "
            "'protocol' for protocol fuzzing, "
            "'resources' for resources endpoints, 'prompts' for prompts endpoints, "
            "'all' for tools + protocol (default: all)"
        ),
    )

    parser.add_argument(
        "--tool",
        type=str,
        help="Optional tool name to fuzz when using --mode tools",
    )

    parser.add_argument(
        "--phase",
        choices=["realistic", "aggressive", "both"],
        default="aggressive",
        help=(
            "Fuzzing phase: 'realistic' for valid data testing, "
            "'aggressive' for attack/edge-case testing, "
            "'both' for two-phase fuzzing (default: aggressive)"
        ),
    )

    parser.add_argument(
        "--protocol-phase",
        choices=["realistic", "aggressive"],
        default="realistic",
        help=(
            "Protocol fuzzing phase: 'realistic' for structured protocol payloads, "
            "'aggressive' for malformed/attack payloads (default: realistic)"
        ),
    )

    parser.add_argument(
        "--protocol",
        type=str,
        choices=["http", "sse", "stdio", "streamablehttp"],
        default="http",
        help="Transport protocol to use (http, sse, stdio, streamablehttp)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        help="Server endpoint (URL for http/sse, command for stdio)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--transport-retries",
        type=int,
        default=1,
        help="Total attempts for transport requests (default: 1)",
    )
    parser.add_argument(
        "--transport-retry-delay",
        type=float,
        default=0.5,
        help="Base delay for transport retries in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--transport-retry-backoff",
        type=float,
        default=2.0,
        help="Backoff multiplier for transport retries (default: 2.0)",
    )
    parser.add_argument(
        "--transport-retry-max-delay",
        type=float,
        default=5.0,
        help="Maximum delay for transport retries in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--transport-retry-jitter",
        type=float,
        default=0.1,
        help="Jitter factor for transport retry delay (default: 0.1)",
    )
    parser.add_argument(
        "--tool-timeout",
        type=float,
        help=(
            "Per-tool call timeout in seconds. Overrides --timeout for individual "
            "tool calls when provided."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    parser.add_argument(
        "--enable-aiomonitor",
        action="store_true",
        help=(
            "Enable AIOMonitor for async debugging "
            "(connect with: telnet localhost 20101)"
        ),
    )

    parser.add_argument(
        "--log-level",
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        help=(
            "Set log verbosity level. Overrides --verbose when provided. "
            "Defaults to WARNING unless --verbose is set (then INFO)."
        ),
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of fuzzing runs per tool (default: 10)",
    )

    parser.add_argument(
        "--runs-per-type",
        type=int,
        default=5,
        help="Number of fuzzing runs per protocol type (default: 5)",
    )
    parser.add_argument(
        "--stateful",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable learned stateful protocol sequences (default: false)",
    )
    parser.add_argument(
        "--stateful-runs",
        type=int,
        default=5,
        help="Number of learned stateful sequences to run (default: 5)",
    )
    parser.add_argument(
        "--havoc",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable stacked corpus mutations (havoc mode)",
    )
    parser.add_argument(
        "--corpus",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable per-target corpus save/load (default: true)",
    )
    parser.add_argument(
        "--protocol-type",
        help="Fuzz only a specific protocol type (when mode is protocol)",
    )
    parser.add_argument(
        "--spec-guard",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Run deterministic spec guard checks before protocol fuzzing "
            "(default: true)"
        ),
    )

    parser.add_argument(
        "--spec-resource-uri",
        help="Resource URI to use for spec guard resources/read checks",
    )

    parser.add_argument(
        "--spec-prompt-name",
        help="Prompt name to use for spec guard prompts/get checks",
    )

    parser.add_argument(
        "--spec-prompt-args",
        help=(
            "JSON string of arguments to use for spec guard prompts/get checks "
            '(e.g., \'{"name":"value"}\')'
        ),
    )

    parser.add_argument(
        "--fs-root",
        help=(
            "Path to a sandbox directory where any file operations from tool calls "
            "will be confined (default: ~/.mcp_fuzzer)"
        ),
    )

    parser.add_argument(
        "--auth-config",
        help="Path to authentication configuration file (JSON format)",
    )
    parser.add_argument(
        "--auth-env",
        action="store_true",
        help="Load authentication from environment variables",
    )

    parser.add_argument(
        "--enable-safety-system",
        action="store_true",
        help=(
            "Enable system-level command blocking (fake executables on PATH) to "
            "prevent external app launches during fuzzing."
        ),
    )
    parser.add_argument(
        "--spec-schema-version",
        help=(
            "Use a specific MCP schema version "
            "(e.g., 2025-06-18) for schema-driven fuzzing."
        ),
    )
    parser.add_argument(
        "--no-safety",
        action="store_true",
        help="Disable argument-level safety filtering (not recommended).",
    )
    parser.add_argument(
        "--safety-report",
        action="store_true",
        help=(
            "Show comprehensive safety report at the end of fuzzing, including "
            "detailed breakdown of all blocked operations."
        ),
    )
    parser.add_argument(
        "--export-safety-data",
        metavar="FILENAME",
        nargs="?",
        const="",
        help=(
            "Export safety data to JSON file. If no filename provided, "
            "uses timestamped filename. Use with --safety-report for best results."
        ),
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIRECTORY",
        default="reports",
        help="Directory to save reports and exports (default: reports)",
    )
    parser.add_argument(
        "--retry-with-safety-on-interrupt",
        action="store_true",
        help=(
            "On Ctrl-C, retry the run once with the system safety enabled if it "
            "was not already enabled."
        ),
    )

    # Network safety controls
    parser.add_argument(
        "--no-network",
        action="store_true",
        help="Disallow network to non-local hosts (localhost/127.0.0.1/::1 only).",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        dest="allow_hosts",
        metavar="HOST",
        help=(
            "Permit additional hostnames when --no-network is used. "
            "Can be specified multiple times."
        ),
    )

    parser.add_argument(
        "--validate-config",
        metavar="CONFIG_FILE",
        help="Validate configuration file and exit",
    )

    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Check environment variables and exit",
    )

    parser.add_argument(
        "--export-csv",
        metavar="FILENAME",
        help="Export fuzzing results to CSV format",
    )

    parser.add_argument(
        "--export-xml",
        metavar="FILENAME",
        help="Export fuzzing results to XML format",
    )

    parser.add_argument(
        "--export-html",
        metavar="FILENAME",
        help="Export fuzzing results to HTML format",
    )

    parser.add_argument(
        "--export-markdown",
        metavar="FILENAME",
        help="Export fuzzing results to Markdown format",
    )

    # Performance and monitoring configuration
    parser.add_argument(
        "--watchdog-check-interval",
        type=float,
        default=1.0,
        help="How often to check processes for hanging (seconds, default: 1.0)",
    )

    parser.add_argument(
        "--watchdog-process-timeout",
        type=float,
        default=30.0,
        help="Time before process is considered hanging (seconds, default: 30.0)",
    )

    parser.add_argument(
        "--watchdog-extra-buffer",
        type=float,
        default=5.0,
        help="Extra time before auto-kill (seconds, default: 5.0)",
    )

    parser.add_argument(
        "--watchdog-max-hang-time",
        type=float,
        default=60.0,
        help="Maximum time before force kill (seconds, default: 60.0)",
    )

    parser.add_argument(
        "--process-max-concurrency",
        type=int,
        default=5,
        help="Maximum concurrent process operations (default: 5)",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=5,
        help="Maximum concurrent client operations (default: 5)",
    )
    parser.add_argument(
        "--process-retry-count",
        type=int,
        default=1,
        help="Number of retries for failed operations (default: 1)",
    )

    parser.add_argument(
        "--process-retry-delay",
        type=float,
        default=1.0,
        help="Delay between retries (seconds, default: 1.0)",
    )

    # Standardized output options
    parser.add_argument(
        "--output-format",
        choices=["json", "yaml", "csv", "xml"],
        default="json",
        help="Output format for standardized reports (default: json)",
    )

    parser.add_argument(
        "--output-types",
        nargs="+",
        choices=[
            "fuzzing_results",
            "error_report",
            "safety_summary",
            "performance_metrics",
            "configuration_dump",
        ],
        help="Specific output types to generate (default: all)",
    )

    parser.add_argument(
        "--output-schema",
        metavar="SCHEMA_FILE",
        help="Path to custom output schema file",
    )

    parser.add_argument(
        "--output-compress",
        action="store_true",
        help="Compress output files",
    )

    parser.add_argument(
        "--output-session-id",
        metavar="SESSION_ID",
        help="Custom session ID for output files",
    )

    return parser


def parse_arguments() -> argparse.Namespace:
    parser = create_argument_parser()
    return parser.parse_args()


__all__ = ["create_argument_parser", "parse_arguments"]
