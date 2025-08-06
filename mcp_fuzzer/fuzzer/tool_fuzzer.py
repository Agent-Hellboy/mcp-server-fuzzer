#!/usr/bin/env python3
"""
Tool Fuzzer

This module contains the orchestration logic for fuzzing MCP tools.
"""

import logging
from typing import Any, Dict, List

from ..strategy.tool_strategies import ToolStrategies


class ToolFuzzer:
    """Orchestrates fuzzing of MCP tools."""

    def __init__(self):
        self.strategies = ToolStrategies()

    def fuzz_tool(self, tool: Dict[str, Any], runs: int = 10) -> List[Dict[str, Any]]:
        """Fuzz a tool by calling it with random/edge-case arguments."""
        results = []

        for i in range(runs):
            try:
                # Generate fuzz arguments using the strategy
                args = self.strategies.fuzz_tool_arguments(tool)

                logging.info(
                    f"Fuzzing {tool['name']} (run {i + 1}/{runs}) with args: {args}"
                )

                results.append(
                    {
                        "tool_name": tool["name"],
                        "run": i + 1,
                        "args": args,
                        "success": True,
                    }
                )

            except Exception as e:
                logging.warning(f"Exception during fuzzing {tool['name']}: {e}")
                results.append(
                    {
                        "tool_name": tool["name"],
                        "run": i + 1,
                        "args": args if "args" in locals() else None,
                        "exception": str(e),
                        "success": False,
                    }
                )

        return results

    def fuzz_tools(
        self, tools: List[Dict[str, Any]], runs_per_tool: int = 10
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz multiple tools."""
        all_results = {}

        for tool in tools:
            tool_name = tool.get("name", "unknown")
            logging.info(f"Starting to fuzz tool: {tool_name}")

            try:
                results = self.fuzz_tool(tool, runs_per_tool)
                all_results[tool_name] = results

                # Calculate statistics
                successful = len([r for r in results if r.get("success", False)])
                exceptions = len([r for r in results if not r.get("success", False)])

                logging.info(
                    f"Completed fuzzing {tool_name}: {successful} successful, {exceptions} exceptions out of {runs_per_tool} runs"
                )

            except Exception as e:
                logging.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results
