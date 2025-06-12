"""
Utility functions for mcp_fuzzer.
"""

from typing import Any, Dict, List

from .client import jsonrpc_request


def get_tools_from_server(url: str) -> List[Dict[str, Any]]:
    """Fetch the list of tools and their schemas from the MCP server using JSON-RPC."""
    response = jsonrpc_request(url, "tools/list")
    # The result is expected to be {"tools": [ ... ]}
    return response.get("tools", [])
