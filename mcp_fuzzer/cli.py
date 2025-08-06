#!/usr/bin/env python3
"""
MCP Fuzzer - CLI Module

This module handles command-line argument parsing and CLI logic for the MCP fuzzer.
"""

import argparse
import logging
import sys
from typing import Any, Dict

from rich.console import Console


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser for the MCP fuzzer."""
    parser = argparse.ArgumentParser(
        description="MCP Fuzzer - Comprehensive fuzzing for MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz tools only
  mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ --runs 10

  # Fuzz protocol types only
  mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 5

  # Fuzz both tools and protocols (default)
  mcp-fuzzer --mode both --protocol http --endpoint http://localhost:8000/mcp/ --runs 10 --runs-per-type 5

  # Fuzz specific protocol type
  mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000/mcp/

  # Fuzz with verbose output
  mcp-fuzzer --mode both --protocol http --endpoint http://localhost:8000/mcp/ --verbose
        """,
    )

    # Mode selection
    parser.add_argument(
        "--mode",
        choices=["tools", "protocol", "both"],
        default="both",
        help="Fuzzing mode: 'tools' for tool fuzzing, 'protocol' for protocol fuzzing, 'both' for both (default: both)",
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
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

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

    return parser


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments and return the parsed namespace."""
    parser = create_argument_parser()
    return parser.parse_args()


def setup_logging(args: argparse.Namespace) -> None:
    """Set up logging based on command line arguments."""
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


def build_unified_client_args(args: argparse.Namespace) -> None:
    """Build sys.argv for the unified client based on parsed arguments."""
    sys.argv = [
        "mcp-fuzzer",
        "--mode",
        args.mode,
        "--protocol",
        args.protocol,
        "--endpoint",
        args.endpoint,
        "--runs",
        str(args.runs),
        "--runs-per-type",
        str(args.runs_per_type),
        "--timeout",
        str(args.timeout),
    ]

    if args.protocol_type:
        sys.argv.extend(["--protocol-type", args.protocol_type])
    if args.verbose:
        sys.argv.append("--verbose")


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

    if args.runs < 1:
        raise ValueError("--runs must be at least 1")

    if args.runs_per_type < 1:
        raise ValueError("--runs-per-type must be at least 1")

    if args.timeout <= 0:
        raise ValueError("--timeout must be positive")


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
        build_unified_client_args(args)
        print_startup_info(args)

        # Import here to avoid circular imports
        import asyncio

        from .client import main as unified_client_main

        asyncio.run(unified_client_main())

    except ValueError as e:
        console = Console()
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        console = Console()
        console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {e}")
        if logging.getLogger().level <= logging.DEBUG:
            import traceback

            console.print(traceback.format_exc())
        sys.exit(1)
