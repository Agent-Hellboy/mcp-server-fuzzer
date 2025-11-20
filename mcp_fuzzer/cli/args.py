#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Any

from ..exceptions import ArgumentValidationError

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
    
    # AIOMonitor integration
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

def _resolve_auth_manager(args: argparse.Namespace):
    """Resolve an AuthManager based on CLI flags or the environment."""
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    auth_config = getattr(args, "auth_config", None)
    auth_env = getattr(args, "auth_env", False)

    if auth_config:
        if cli_module and hasattr(cli_module, "load_auth_config"):
            return cli_module.load_auth_config(auth_config)  # type: ignore[attr-defined]
        from ..auth import load_auth_config as _load_auth_config

        return _load_auth_config(auth_config)

    if auth_env:
        if cli_module and hasattr(cli_module, "setup_auth_from_env"):
            return cli_module.setup_auth_from_env()  # type: ignore[attr-defined]
        from ..auth import setup_auth_from_env as _setup_auth_from_env

        return _setup_auth_from_env()

    return None

def build_unified_client_args(args: argparse.Namespace) -> dict[str, Any]:
    client_args = {
        "mode": args.mode,
        "phase": args.phase,
        "protocol": args.protocol,
        "endpoint": args.endpoint,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "runs": args.runs,
        "runs_per_type": args.runs_per_type,
        "safety_enabled": not getattr(args, "no_safety", False),
    }

    client_args["fs_root"] = getattr(args, "fs_root", None)

    if args.protocol_type:
        client_args["protocol_type"] = args.protocol_type

    auth_manager = _resolve_auth_manager(args)
    if auth_manager:
        client_args["auth_manager"] = auth_manager

    fs_root_value = getattr(args, "fs_root", None)
    if fs_root_value:
        client_args["fs_root"] = fs_root_value

    return client_args

def print_startup_info(args: argparse.Namespace) -> None:
    # Resolve Console via package so tests can patch mcp_fuzzer.cli.Console
    cli_module = sys.modules.get("mcp_fuzzer.cli")
    from rich.console import Console as RichConsole

    ConsoleClass = (
        getattr(cli_module, "Console", RichConsole) if cli_module else RichConsole
    )
    console = ConsoleClass()
    console.print(f"[bold blue]MCP Fuzzer - {args.mode.upper()} Mode[/bold blue]")
    console.print(f"Protocol: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")

def get_cli_config() -> dict[str, Any]:
    """Get CLI configuration merged from env, file, and CLI flags.

    Order of precedence (lowest to highest):
    - Environment defaults
    - Configuration file (explicit or discovered)
    - CLI arguments
    """
    parser = create_argument_parser()
    args = parser.parse_args()
    validate_arguments(args)

    config_dict = _load_config_from_sources(args)
    _sync_global_config(config_dict)
    return config_dict


def _load_config_from_sources(args: argparse.Namespace) -> dict[str, Any]:
    """Load config via unified pipeline (env -> file -> CLI overrides)."""
    from ..config.loader import load_config, load_custom_transports

    config_dict, _model = load_config(
        config_path=getattr(args, "config", None),
        cli_overrides=vars(args),
    )
    load_custom_transports(config_dict)
    return config_dict


def _sync_global_config(config_dict: dict[str, Any]) -> None:
    """Update the global config store for legacy consumers."""
    from ..config import config as global_config

    global_config.clear()
    global_config.update(config_dict)
def validate_arguments(args: argparse.Namespace) -> None:
    # Check if this is a utility command that doesn't need endpoint
    is_utility_command = (
        getattr(args, 'check_env', False) or
        getattr(args, 'validate_config', None) is not None
    )

    # Require endpoint for non-utility commands
    if not is_utility_command and not getattr(args, 'endpoint', None):
        raise ArgumentValidationError("--endpoint is required for fuzzing operations")

    if args.mode == "protocol" and not args.protocol_type:
        pass

    if args.protocol_type and args.mode != "protocol":
        raise ArgumentValidationError(
            "--protocol-type can only be used with --mode protocol"
        )

    if hasattr(args, "runs") and args.runs is not None:
        if not isinstance(args.runs, int) or args.runs < 1:
            raise ArgumentValidationError("--runs must be at least 1")

    if hasattr(args, "runs_per_type") and args.runs_per_type is not None:
        if not isinstance(args.runs_per_type, int) or args.runs_per_type < 1:
            raise ArgumentValidationError("--runs-per-type must be at least 1")

    if hasattr(args, "timeout") and args.timeout is not None:
        if not isinstance(args.timeout, (int, float)) or args.timeout <= 0:
            raise ArgumentValidationError("--timeout must be positive")

    if hasattr(args, "endpoint") and args.endpoint is not None:
        if not args.endpoint.strip():
            raise ArgumentValidationError("--endpoint cannot be empty")
