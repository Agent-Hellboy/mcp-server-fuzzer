#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Any, Dict

from rich.console import Console

from ..safety_system.safety import (
    safety_filter,
    disable_safety,
    load_safety_plugin,
)
from ..config import config


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

  # Fuzz both tools and protocols (default)
  mcp-fuzzer --mode both --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs 10 --runs-per-type 5

  # Fuzz specific protocol type
  mcp-fuzzer --mode protocol --protocol-type InitializeRequest \
    --protocol http --endpoint http://localhost:8000/mcp/

  # Fuzz with verbose output
  mcp-fuzzer --mode both --protocol http \
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
        choices=["tools", "protocol", "both"],
        default="both",
        help=(
            "Fuzzing mode: 'tools' for tool fuzzing, 'protocol' for protocol fuzzing, "
            "'both' for both (default: both)"
        ),
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
        "--tool-timeout",
        type=float,
        help=(
            "Per-tool call timeout in seconds. Overrides --timeout for individual "
            "tool calls when provided."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
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
        "--protocol-type",
        help="Fuzz only a specific protocol type (when mode is protocol)",
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
        "--safety-plugin",
        help=(
            "Dotted path to a custom safety provider module. The module must expose "
            "get_safety() or a 'safety' object implementing SafetyProvider."
        ),
    )
    parser.add_argument(
        "--no-safety",
        action="store_true",
        help="Disable argument-level safety filtering (not recommended).",
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
        help=("Disallow network to non-local hosts (localhost/127.0.0.1/::1 only)."),
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
        help="Maximum concurrent operations (default: 5)",
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


def setup_logging(args: argparse.Namespace) -> None:
    if getattr(args, "log_level", None):
        level = getattr(logging, args.log_level)
    else:
        level = logging.INFO if getattr(args, "verbose", False) else logging.WARNING

    # Configure efficient logging with buffering
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,  # Override any existing configuration
    )

    # Optimize logging for performance
    logging.getLogger().setLevel(level)

    # Reduce logging from noisy modules
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("psutil").setLevel(logging.WARNING)


def build_unified_client_args(args: argparse.Namespace) -> Dict[str, Any]:
    client_args = {
        "mode": args.mode,
        "phase": args.phase,
        "protocol": args.protocol,
        "endpoint": args.endpoint,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "runs": args.runs,
        "runs_per_type": args.runs_per_type,
    }

    if args.protocol_type:
        client_args["protocol_type"] = args.protocol_type

    # Resolve auth helpers via the package namespace so tests can patch
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    if args.auth_config:
        if cli_module and hasattr(cli_module, "load_auth_config"):
            client_args["auth_manager"] = cli_module.load_auth_config(args.auth_config)  # type: ignore[attr-defined]
        else:
            from ..auth import load_auth_config as _load_auth_config

            client_args["auth_manager"] = _load_auth_config(args.auth_config)
    elif args.auth_env:
        if cli_module and hasattr(cli_module, "setup_auth_from_env"):
            client_args["auth_manager"] = cli_module.setup_auth_from_env()  # type: ignore[attr-defined]
        else:
            from ..auth import setup_auth_from_env as _setup_auth_from_env

            client_args["auth_manager"] = _setup_auth_from_env()

    fs_root_value = getattr(args, "fs_root", None)
    if fs_root_value:
        try:
            safety_filter.set_fs_root(fs_root_value)
            logging.info(f"Filesystem sandbox root set to: {fs_root_value}")
        except Exception as e:
            logging.warning(f"Failed to set fs-root '{fs_root_value}': {e}")

    plugin = getattr(args, "safety_plugin", None)
    if plugin:
        try:
            if cli_module and hasattr(cli_module, "load_safety_plugin"):
                cli_module.load_safety_plugin(plugin)  # type: ignore[attr-defined]
            else:
                load_safety_plugin(plugin)
            logging.info(f"Loaded safety plugin: {plugin}")
        except Exception as e:
            logging.warning(f"Failed to load safety plugin '{plugin}': {e}")
    if getattr(args, "no_safety", False):
        # Resolve via package for tests to patch
        if cli_module and hasattr(cli_module, "disable_safety"):
            cli_module.disable_safety()  # type: ignore[attr-defined]
        else:
            disable_safety()
        logging.warning("Safety filtering disabled via --no-safety")

    return client_args


def print_startup_info(args: argparse.Namespace) -> None:
    # Resolve Console via package so tests can patch mcp_fuzzer.cli.Console
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    ConsoleClass = getattr(cli_module, "Console", Console) if cli_module else Console
    console = ConsoleClass()
    console.print(f"[bold blue]MCP Fuzzer - {args.mode.upper()} Mode[/bold blue]")
    console.print(f"Protocol: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")


def get_cli_config() -> Dict[str, Any]:
    """Get CLI configuration as a dictionary for external callers/tests.

    Resolve helpers through the package namespace so unit tests patching
    mcp_fuzzer.cli.* take effect.
    """
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    _parse = (
        getattr(cli_module, "parse_arguments", parse_arguments)
        if cli_module
        else parse_arguments
    )
    _validate = (
        getattr(cli_module, "validate_arguments", validate_arguments)
        if cli_module
        else validate_arguments
    )
    _setup = (
        getattr(cli_module, "setup_logging", setup_logging)
        if cli_module
        else setup_logging
    )

    args = _parse()

    # Debug logging to see what arguments are parsed
    logging.debug(f"Parsed args: {args}")
    logging.debug(
        f"Export flags: csv={getattr(args, 'export_csv', 'NOT_SET')}, "
        f"xml={getattr(args, 'export_xml', 'NOT_SET')}, "
        f"html={getattr(args, 'export_html', 'NOT_SET')}, "
        f"md={getattr(args, 'export_markdown', 'NOT_SET')}"
    )

    # Load configuration file if specified
    if args.config:
        from ..config_loader import load_config_file
        from ..exceptions import ConfigFileError

        try:
            config_data = load_config_file(args.config)
            config.update(config_data)
        except Exception as e:
            error_msg = f"Failed to load configuration file '{args.config}': {e}"
            raise ConfigFileError(error_msg)
    else:
        # Try to find and load a configuration file in default locations
        try:
            from ..config_loader import apply_config_file

            apply_config_file()
        except Exception as e:
            logging.debug(f"Error loading default configuration file: {e}")

    # CLI arguments take precedence over configuration file
    _validate(args)
    _setup(args)

    # Update centralized configuration with CLI arguments
    config.update(
        {
            "mode": args.mode,
            "phase": args.phase,
            "protocol": args.protocol,
            "endpoint": args.endpoint,
            "timeout": args.timeout,
            "tool_timeout": getattr(args, "tool_timeout", None),
            "fs_root": getattr(args, "fs_root", None),
            "verbose": args.verbose,
            "runs": args.runs,
            "runs_per_type": args.runs_per_type,
            "protocol_type": args.protocol_type,
            "enable_safety_system": getattr(args, "enable_safety_system", False),
            "safety_report": getattr(args, "safety_report", False),
            "export_safety_data": getattr(args, "export_safety_data", None),
            "output_dir": getattr(args, "output_dir", "reports"),
            "safety_plugin": getattr(args, "safety_plugin", None),
            "no_safety": getattr(args, "no_safety", False),
            "retry_with_safety_on_interrupt": getattr(
                args, "retry_with_safety_on_interrupt", False
            ),
            "log_level": getattr(args, "log_level", None),
            "no_network": getattr(args, "no_network", False),
            "allow_hosts": getattr(args, "allow_hosts", None),
            "validate_config": getattr(args, "validate_config", None),
            "check_env": getattr(args, "check_env", False),
            "export_csv": getattr(args, "export_csv", None),
            "export_xml": getattr(args, "export_xml", None),
            "export_html": getattr(args, "export_html", None),
            "export_markdown": getattr(args, "export_markdown", None),
            "watchdog_check_interval": getattr(args, "watchdog_check_interval", 1.0),
            "watchdog_process_timeout": getattr(args, "watchdog_process_timeout", 30.0),
            "watchdog_extra_buffer": getattr(args, "watchdog_extra_buffer", 5.0),
            "watchdog_max_hang_time": getattr(args, "watchdog_max_hang_time", 60.0),
            "process_max_concurrency": getattr(args, "process_max_concurrency", 5),
            "process_retry_count": getattr(args, "process_retry_count", 1),
            "process_retry_delay": getattr(args, "process_retry_delay", 1.0),
            "output_format": getattr(args, "output_format", "json"),
            "output_types": getattr(args, "output_types", None),
            "output_schema": getattr(args, "output_schema", None),
            "output_compress": getattr(args, "output_compress", False),
            "output_session_id": getattr(args, "output_session_id", None),
        }
    )

    return {
        "mode": args.mode,
        "phase": args.phase,
        "protocol": args.protocol,
        "endpoint": args.endpoint,
        "timeout": args.timeout,
        "tool_timeout": getattr(args, "tool_timeout", None),
        "fs_root": getattr(args, "fs_root", None),
        "verbose": args.verbose,
        "runs": args.runs,
        "runs_per_type": args.runs_per_type,
        "protocol_type": args.protocol_type,
        "enable_safety_system": getattr(args, "enable_safety_system", False),
        "safety_report": getattr(args, "safety_report", False),
        "export_safety_data": getattr(args, "export_safety_data", None),
        "output_dir": getattr(args, "output_dir", "reports"),
        "safety_plugin": getattr(args, "safety_plugin", None),
        "no_safety": getattr(args, "no_safety", False),
        "retry_with_safety_on_interrupt": getattr(
            args, "retry_with_safety_on_interrupt", False
        ),
        "log_level": getattr(args, "log_level", None),
        "no_network": getattr(args, "no_network", False),
        "allow_hosts": getattr(args, "allow_hosts", None),
        "validate_config": getattr(args, "validate_config", None),
        "check_env": getattr(args, "check_env", False),
        "export_csv": getattr(args, "export_csv", None),
        "export_xml": getattr(args, "export_xml", None),
        "export_html": getattr(args, "export_html", None),
        "export_markdown": getattr(args, "export_markdown", None),
    }


def validate_arguments(args: argparse.Namespace) -> None:
    # Check if this is a utility command that doesn't need endpoint
    is_utility_command = (
        getattr(args, 'check_env', False) or
        getattr(args, 'validate_config', None) is not None
    )

    # Require endpoint for non-utility commands
    if not is_utility_command and not getattr(args, 'endpoint', None):
        raise ValueError("--endpoint is required for fuzzing operations")

    if args.mode == "protocol" and not args.protocol_type:
        pass

    if args.protocol_type and args.mode != "protocol":
        raise ValueError("--protocol-type can only be used with --mode protocol")

    if hasattr(args, "runs") and args.runs is not None:
        if not isinstance(args.runs, int) or args.runs < 1:
            raise ValueError("--runs must be at least 1")

    if hasattr(args, "runs_per_type") and args.runs_per_type is not None:
        if not isinstance(args.runs_per_type, int) or args.runs_per_type < 1:
            raise ValueError("--runs-per-type must be at least 1")

    if hasattr(args, "timeout") and args.timeout is not None:
        if not isinstance(args.timeout, (int, float)) or args.timeout <= 0:
            raise ValueError("--timeout must be positive")

    if hasattr(args, "endpoint") and args.endpoint is not None:
        if not args.endpoint.strip():
            raise ValueError("--endpoint cannot be empty")
