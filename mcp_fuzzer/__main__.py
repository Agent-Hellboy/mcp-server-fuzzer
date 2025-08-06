#!/usr/bin/env python3
"""
MCP Fuzzer - Main Entry Point

This module provides the main entry point for the MCP fuzzer, supporting both
tool fuzzing and protocol fuzzing modes using the unified client.
"""

import argparse
import asyncio
import logging
import sys

from rich.console import Console

from .client import main as unified_client_main

logging.basicConfig(level=logging.INFO)
console = Console()


def main():
    """Main entry point for the MCP fuzzer."""
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

    args = parser.parse_args()

    # Set up logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create sys.argv for unified client
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

    # Run unified client
    console.print(f"[bold blue]MCP Fuzzer - {args.mode.upper()} Mode[/bold blue]")
    console.print(f"Protocol: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")

    asyncio.run(unified_client_main())


if __name__ == "__main__":
    main()
