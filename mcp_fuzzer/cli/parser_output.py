"""Output, logging, and runtime CLI arguments."""

from __future__ import annotations

import argparse


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
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
            "Set log verbosity level (default: WARNING). Use INFO or DEBUG for "
            "progress and diagnostic detail."
        ),
    )

    parser.add_argument(
        "--output-dir",
        metavar="DIRECTORY",
        default=None,
        help="Directory to save reports and exports (default: reports)",
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
        "--max-concurrency",
        type=int,
        default=5,
        help="Maximum concurrent client operations (default: 5)",
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
