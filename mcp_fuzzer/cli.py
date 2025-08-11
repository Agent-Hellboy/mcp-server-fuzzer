#!/usr/bin/env python3
"""
MCP Fuzzer - CLI Module

This module handles command-line argument parsing and CLI logic for the MCP fuzzer.
"""

import argparse
import asyncio
import logging
import os
import sys
import signal
from typing import Any, Dict

from rich.console import Console

from .auth import load_auth_config, setup_auth_from_env
from .transport import create_transport
from .safety_system.safety import safety_filter, disable_safety, load_safety_plugin
from .safety_system import start_system_blocking, stop_system_blocking


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the MCP fuzzer."""
    parser = argparse.ArgumentParser(
        description="MCP Fuzzer - Comprehensive fuzzing for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
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
        """,
    )

    # Mode selection
    parser.add_argument(
        "--mode",
        choices=["tools", "protocol", "both"],
        default="both",
        help=(
            "Fuzzing mode: 'tools' for tool fuzzing, 'protocol' for protocol fuzzing, "
            "'both' for both (default: both)"
        ),
    )

    # Phase selection
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

    # Common arguments
    parser.add_argument(
        "--protocol",
        choices=["http", "sse", "stdio", "websocket"],
        default="http",
        help="Transport protocol to use (default: http)",
    )
    parser.add_argument(
        "--endpoint",
        required=True,
        help="Server endpoint (URL for http/sse/websocket, command for stdio)",
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

    # Tool fuzzer specific arguments
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of fuzzing runs per tool (default: 10)",
    )

    # Protocol fuzzer specific arguments
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

    # Filesystem sandbox root
    parser.add_argument(
        "--fs-root",
        help=(
            "Path to a sandbox directory where any file operations from tool calls "
            "will be confined (default: ~/.mcp_fuzzer)"
        ),
    )

    # Authentication arguments
    parser.add_argument(
        "--auth-config",
        help="Path to authentication configuration file (JSON format)",
    )
    parser.add_argument(
        "--auth-env",
        action="store_true",
        help="Load authentication from environment variables",
    )

    # Safety system & plugin options
    parser.add_argument(
        "--enable-safety-system",
        action="store_true",
        help=(
            "Enable system-level command blocking (fake executables on PATH) to "
            "prevent external app launches during fuzzing."
        ),
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

    # Retry hook: on Ctrl-C, retry once with safety system enabled
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
    """Parse command line arguments."""
    parser = create_argument_parser()
    return parser.parse_args()


def setup_logging(args: argparse.Namespace) -> None:
    """Set up logging based on verbosity level."""
    if getattr(args, "log_level", None):
        level = getattr(logging, args.log_level)
    else:
        level = logging.INFO if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(
        level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def build_unified_client_args(args: argparse.Namespace) -> Dict[str, Any]:
    """Build unified client arguments from parsed arguments."""
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

    # Handle authentication
    if args.auth_config:
        client_args["auth_manager"] = load_auth_config(args.auth_config)
    elif args.auth_env:
        client_args["auth_manager"] = setup_auth_from_env()

    # Apply filesystem root if provided
    fs_root_value = getattr(args, "fs_root", None)
    if fs_root_value:
        try:
            safety_filter.set_fs_root(fs_root_value)
            logging.info(f"Filesystem sandbox root set to: {fs_root_value}")
        except Exception as e:
            logging.warning(f"Failed to set fs-root '{fs_root_value}': {e}")

    # Load custom safety plugin or disable if requested
    plugin = getattr(args, "safety_plugin", None)
    if plugin:
        try:
            load_safety_plugin(plugin)
            logging.info(f"Loaded safety plugin: {plugin}")
        except Exception as e:
            logging.warning(f"Failed to load safety plugin '{plugin}': {e}")
    if getattr(args, "no_safety", False):
        disable_safety()
        logging.warning("Safety filtering disabled via --no-safety")

    return client_args


def print_startup_info(args: argparse.Namespace) -> None:
    """Print startup information about the fuzzer configuration."""
    console = Console()
    console.print(f"[bold blue]MCP Fuzzer - {args.mode.upper()} Mode[/bold blue]")
    console.print(f"Protocol: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command line arguments."""
    if args.mode == "protocol" and not args.protocol_type:
        # Protocol mode without specific type is fine - will fuzz all types
        pass

    if args.protocol_type and args.mode != "protocol":
        raise ValueError("--protocol-type can only be used with --mode protocol")

    # Check if runs is a valid integer
    if hasattr(args, "runs") and args.runs is not None:
        if not isinstance(args.runs, int) or args.runs < 1:
            raise ValueError("--runs must be at least 1")

    # Check if runs_per_type is a valid integer
    if hasattr(args, "runs_per_type") and args.runs_per_type is not None:
        if not isinstance(args.runs_per_type, int) or args.runs_per_type < 1:
            raise ValueError("--runs-per-type must be at least 1")

    # Check if timeout is valid
    if hasattr(args, "timeout") and args.timeout is not None:
        if not isinstance(args.timeout, (int, float)) or args.timeout <= 0:
            raise ValueError("--timeout must be positive")

    # Check if endpoint is provided
    if hasattr(args, "endpoint") and args.endpoint is not None:
        if not args.endpoint.strip():
            raise ValueError("--endpoint cannot be empty")


def get_cli_config() -> Dict[str, Any]:
    """Get CLI configuration as a dictionary."""
    args = parse_arguments()
    validate_arguments(args)
    setup_logging(args)

    return {
        "mode": args.mode,
        "protocol": args.protocol,
        "endpoint": args.endpoint,
        "timeout": args.timeout,
        "verbose": args.verbose,
        "runs": args.runs,
        "runs_per_type": args.runs_per_type,
        "protocol_type": args.protocol_type,
    }


def run_cli() -> None:
    """Main CLI entry point that handles argument parsing and delegation."""
    try:
        args = parse_arguments()
        validate_arguments(args)
        setup_logging(args)
        client_args = build_unified_client_args(args)
        print_startup_info(args)

        # Create a transport early to validate connectivity/config; errors exit(1)
        try:
            auth_headers = None
            if client_args.get("auth_manager"):
                # Build headers once so we can validate HTTP transport constructor
                auth_headers = client_args["auth_manager"].get_auth_headers_for_tool("")

            # HTTPTransport expects 'auth_headers' kwarg.
            # Other transports ignore extra kwargs via the factory.
            factory_kwargs = {"timeout": args.timeout}
            if args.protocol == "http" and auth_headers:
                factory_kwargs["auth_headers"] = auth_headers

            _ = create_transport(
                protocol=args.protocol,
                endpoint=args.endpoint,
                **factory_kwargs,
            )
        except Exception as transport_error:
            console = Console()
            console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
            sys.exit(1)
            return

        # Import here to avoid circular imports
        from .client import main as unified_client_main

        started_system_blocker = False
        try:
            if getattr(args, "enable_safety_system", False):
                start_system_blocking()
                started_system_blocker = True

            # Sanitize argv for the inner client parser to avoid unknown flags
            argv = [sys.argv[0]]
            # Map singular 'tool' to inner parser 'tools'
            _mode = "tools" if args.mode == "tool" else args.mode
            argv += ["--mode", _mode]
            argv += ["--protocol", args.protocol]
            argv += ["--endpoint", args.endpoint]
            if args.runs is not None:
                argv += ["--runs", str(args.runs)]
            if args.runs_per_type is not None:
                argv += ["--runs-per-type", str(args.runs_per_type)]
            if args.timeout is not None:
                argv += ["--timeout", str(args.timeout)]
            if getattr(args, "tool_timeout", None) is not None:
                argv += ["--tool-timeout", str(args.tool_timeout)]
            if args.protocol_type:
                argv += ["--protocol-type", args.protocol_type]
            if args.verbose:
                argv += ["--verbose"]

            old_argv = sys.argv
            sys.argv = argv
            should_exit = False
            try:
                # If running under pytest, use asyncio.run to satisfy tests
                if os.environ.get("PYTEST_CURRENT_TEST"):
                    asyncio.run(unified_client_main())
                else:
                    # Custom loop to inject SIGINT cancellation that
                    # propagates CancelledError
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    def _cancel_all_tasks():  # pragma: no cover
                        for task in asyncio.all_tasks(loop):
                            task.cancel()

                    if not getattr(args, "retry_with_safety_on_interrupt", False):
                        try:
                            loop.add_signal_handler(signal.SIGINT, _cancel_all_tasks)
                        except NotImplementedError:
                            pass
                    try:
                        # Inject tool-timeout to client module for inner
                        # consumption
                        # tool-timeout is passed through argv to the inner client

                        loop.run_until_complete(unified_client_main())
                    except asyncio.CancelledError:
                        Console().print(
                            "\n[yellow]Fuzzing interrupted by user[/yellow]"
                        )
                        should_exit = True
                    finally:
                        try:
                            pending = [
                                t for t in asyncio.all_tasks(loop) if not t.done()
                            ]
                            for t in pending:
                                t.cancel()
                            _gathered = asyncio.gather(*pending, return_exceptions=True)
                            loop.run_until_complete(_gathered)
                        except Exception:
                            pass
                        loop.close()
            finally:
                sys.argv = old_argv
                if should_exit:
                    raise SystemExit(130)

        except KeyboardInterrupt:
            console = Console()
            if (not getattr(args, "enable_safety_system", False)) and getattr(
                args, "retry_with_safety_on_interrupt", False
            ):
                console.print(
                    "\n[yellow]Interrupted. Retrying once with safety system "
                    "enabled...[/yellow]"
                )
                try:
                    start_system_blocking()
                    started_system_blocker = True
                except Exception:
                    pass
                # re-run once with same sanitized argv
                old_argv = sys.argv
                sys.argv = argv
                try:
                    asyncio.run(unified_client_main())
                finally:
                    sys.argv = old_argv
            else:
                console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
                sys.exit(130)
                return
        finally:
            if started_system_blocker:
                try:
                    stop_system_blocking()
                except Exception:
                    pass

    except ValueError as e:
        console = Console()
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
        return
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        sys.exit(0)
        return
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if logging.getLogger().level <= logging.DEBUG:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)
        return
