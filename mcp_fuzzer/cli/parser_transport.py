"""Transport-related CLI arguments."""

from __future__ import annotations

import argparse


def add_transport_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--protocol",
        type=str,
        choices=["http", "https", "sse", "stdio", "streamablehttp"],
        default="http",
        help="Transport protocol to use (http, https, sse, stdio, streamablehttp)",
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
