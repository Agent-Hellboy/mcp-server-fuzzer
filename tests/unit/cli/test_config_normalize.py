#!/usr/bin/env python3
"""Tests for nested config normalization onto CLI args."""

from __future__ import annotations

import argparse

from mcp_fuzzer.cli.config_normalize import apply_nested_config_to_args
from mcp_fuzzer.cli.parser import create_argument_parser
from mcp_fuzzer.config import config_mediator


def test_apply_nested_output_section_fields():
    config_mediator.update(
        {
            "output": {
                "directory": "/tmp/reports",
                "format": "markdown",
                "compress": True,
                "types": ["json", "csv"],
                "schema": "v1",
            }
        }
    )
    parser = create_argument_parser()
    args = parser.parse_args(
        ["--mode", "tools", "--endpoint", "http://localhost/mcp"]
    )
    apply_nested_config_to_args(args, parser)
    assert args.output_dir == "/tmp/reports"
    assert args.output_format == "markdown"
    assert args.output_compress is True
    assert args.output_types == ["json", "csv"]
    assert args.output_schema == "v1"


def test_apply_nested_output_does_not_override_explicit_cli_value():
    config_mediator.update({"output": {"directory": "/from/config"}})
    parser = create_argument_parser()
    args = parser.parse_args(
        [
            "--mode",
            "tools",
            "--endpoint",
            "http://localhost/mcp",
            "--output-dir",
            "/from/cli",
        ]
    )
    apply_nested_config_to_args(args, parser)
    assert args.output_dir == "/from/cli"


def test_apply_if_default_handles_suppress_default():
    config_mediator.update({"output": {"schema": "custom"}})
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-schema", default=argparse.SUPPRESS)
    args = parser.parse_args([])
    apply_nested_config_to_args(args, parser)
    assert args.output_schema == "custom"
