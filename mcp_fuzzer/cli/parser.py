#!/usr/bin/env python3
"""Argument parser for the MCP fuzzer CLI."""

from __future__ import annotations

import argparse

from ..version import VERSION
from .parser_audit import add_audit_arguments
from .parser_fuzz import add_fuzz_arguments
from .parser_output import add_output_arguments
from .parser_transport import add_transport_arguments


def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-fuzzer",
        description=(
            "MCP Fuzzer - Evidence-producing security assessment for MCP servers"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            """
Examples:
  # Establish a reproducible tool baseline
  mcp-fuzzer --mode tools --protocol http \
    --endpoint http://localhost:8000/mcp/ --phase realistic --runs 10 --seed 42

  # Fuzz protocol types only
  mcp-fuzzer --mode protocol --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs-per-type 5

  # Run tool metadata and output security checks
  mcp-fuzzer --mode tools --phase aggressive --security-audit \
    --protocol http --endpoint http://localhost:8000/mcp/ --runs 10

  # Contain a local stdio target
  mcp-fuzzer --mode all --protocol stdio --endpoint "python my_server.py" \
    --enable-safety-system --fs-root ./fuzz-sandbox --no-network

  # Focus one tool and keep the run reproducible
  mcp-fuzzer --mode tools --tool analyze_repository --protocol http \
    --endpoint http://localhost:8000/mcp/ --runs 10 --seed 42

  # Fuzz with diagnostic logging
  mcp-fuzzer --mode all --protocol http \
    --endpoint http://localhost:8000/mcp/ --log-level INFO
            """
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s v{VERSION}",
        help="Show version and exit",
    )

    parser.add_argument(
        "--config",
        "-c",
        help="Path to configuration file (YAML: .yml or .yaml)",
        default=None,
    )

    add_fuzz_arguments(parser)
    add_transport_arguments(parser)
    add_output_arguments(parser)
    add_audit_arguments(parser)

    return parser


def parse_arguments() -> argparse.Namespace:
    parser = create_argument_parser()
    return parser.parse_args()


__all__ = ["create_argument_parser", "parse_arguments"]
