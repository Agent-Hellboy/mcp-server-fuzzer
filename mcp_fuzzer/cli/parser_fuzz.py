"""Fuzzing-mode CLI arguments."""

from __future__ import annotations

import argparse


def add_fuzz_arguments(parser: argparse.ArgumentParser) -> None:
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
            "(e.g., 2025-11-25) for schema-driven fuzzing."
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
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible fuzz payload generation",
    )

    parser.add_argument(
        "--retry-with-safety-on-interrupt",
        action="store_true",
        help=(
            "On Ctrl-C, retry the run once with the system safety enabled if it "
            "was not already enabled."
        ),
    )
