#!/usr/bin/env python3
import argparse
import logging
import sys
from typing import Any, Dict

from rich.console import Console

from ..safety_system.safety import safety_filter, disable_safety, load_safety_plugin


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
        choices=["http", "sse", "stdio"],
        default="http",
        help="Transport protocol to use (http, sse, stdio)",
    )
    parser.add_argument(
        "--endpoint",
        type=str,
        required=True,
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

    return parser


def parse_arguments() -> argparse.Namespace:
    parser = create_argument_parser()
    return parser.parse_args()


def setup_logging(args: argparse.Namespace) -> None:
    if getattr(args, "log_level", None):
        level = getattr(logging, args.log_level)
    else:
        level = logging.INFO if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def build_unified_client_args(args: argparse.Namespace) -> Dict[str, Any]:
    client_args = {
        "mode": args.mode,
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
    _validate(args)
    _setup(args)

    return {
        "mode": args.mode,
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
    }


def validate_arguments(args: argparse.Namespace) -> None:
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
