#!/usr/bin/env python3
"""
MCP Fuzzer - Main Entry Point

This module provides the main entry point for the MCP fuzzer,
delegating to the CLI module.
"""

from .cli import run_cli


def main():
    """Main entry point for the MCP fuzzer."""
    run_cli()


def run():
    """Entry point for the command line tool."""
    run_cli()


if __name__ == "__main__":
    main()
