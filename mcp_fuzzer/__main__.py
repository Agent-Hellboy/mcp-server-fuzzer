#!/usr/bin/env python3
"""
Entry point for running mcp_fuzzer as a module.
"""

import asyncio

from .client import main


def run():
    """Entry point for the mcp-fuzzer command."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
