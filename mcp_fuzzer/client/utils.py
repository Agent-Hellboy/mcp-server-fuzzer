#!/usr/bin/env python3
"""
Client Utilities

This module provides utility functions for the MCP Fuzzer client.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional


def get_tool_name(tool: Dict[str, Any]) -> str:
    """
    Get the name of a tool, with fallback to 'unknown'.

    Args:
        tool: Tool definition dictionary

    Returns:
        Tool name or 'unknown' if not found
    """
    return tool.get("name", "unknown")


def create_error_result(error_message: str) -> Dict[str, Any]:
    """
    Create a standardized error result.

    Args:
        error_message: Error message

    Returns:
        Dictionary with error information
    """
    return {
        "error": error_message,
        "success": False,
    }


def calculate_success_rate(results: List[Dict[str, Any]]) -> float:
    """
    Calculate success rate from a list of results.

    Args:
        results: List of result dictionaries

    Returns:
        Success rate as a float between 0 and 1
    """
    if not results:
        return 0.0

    successful = sum(1 for r in results if r.get("success", False))
    return successful / len(results)


async def with_timeout(
    coro, timeout: Optional[float] = None, default_result: Any = None
) -> Any:
    """
    Run a coroutine with a timeout.

    Args:
        coro: Coroutine to run
        timeout: Timeout in seconds (None for no timeout)
        default_result: Result to return on timeout

    Returns:
        Result of the coroutine or default_result on timeout
    """
    if timeout is None:
        return await coro

    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logging.warning(f"Operation timed out after {timeout} seconds")
        return default_result
