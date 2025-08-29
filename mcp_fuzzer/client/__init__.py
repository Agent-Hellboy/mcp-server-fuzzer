#!/usr/bin/env python3
"""
MCP Fuzzer Client Package

This package provides a modular client for fuzzing MCP servers.
"""

import logging
from typing import List, Optional

from ..transport import create_transport
from .base import MCPFuzzerClient

# For backward compatibility
UnifiedMCPFuzzerClient = MCPFuzzerClient

async def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI application.
    
    Args:
        argv: Command line arguments (optional)
        
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    from ..cli.args import get_cli_config
    
    # Get configuration from CLI args, env vars, and config files
    config = get_cli_config()
    
    # Create transport based on configuration
    transport = create_transport(
        protocol=config["protocol"],
        endpoint=config["endpoint"],
        timeout=config.get("timeout"),
    )
    
    # Create client
    client = MCPFuzzerClient(
        transport=transport,
        auth_manager=config.get("auth_manager"),
        tool_timeout=config.get("timeout"),
        max_concurrency=config.get("max_concurrency", 5),
    )
    
    try:
        # Execute fuzzing based on mode
        if config["mode"] == "tools":
            if config.get("phase") == "both":
                await client.fuzz_all_tools_both_phases(
                    runs_per_phase=config.get("runs", 10)
                )
            else:
                await client.fuzz_all_tools(runs=config.get("runs", 10))
        elif config["mode"] == "tool":
            if config.get("phase") == "both":
                await client.fuzz_tool_both_phases(
                    config["tool"], 
                    runs_per_phase=config.get("runs", 10)
                )
            else:
                await client.fuzz_tool(config["tool"], runs=config.get("runs", 10))
        elif config["mode"] == "protocol":
            if config.get("protocol_type"):
                await client.fuzz_protocol_type(
                    config["protocol_type"], 
                    runs=config.get("runs_per_type", 10)
                )
            else:
                await client.fuzz_all_protocol_types(
                    runs_per_type=config.get("runs_per_type", 10)
                )
        else:
            logging.error(f"Unknown mode: {config['mode']}")
            return 1
            
        return 0
    except Exception as e:
        logging.error(f"Error during fuzzing: {e}")
        return 1
    finally:
        # Ensure proper shutdown
        await client.shutdown()

__all__ = ["MCPFuzzerClient", "UnifiedMCPFuzzerClient", "main"]
