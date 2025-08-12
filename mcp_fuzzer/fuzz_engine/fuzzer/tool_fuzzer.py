#!/usr/bin/env python3
"""
Tool Fuzzer

This module contains the orchestration logic for fuzzing MCP tools.
"""

import logging
from typing import Any, Dict, List

from ...safety_system.safety import (
    safety_filter,
    is_safe_tool_call,
    sanitize_tool_call,
)
from ..strategy import ToolStrategies


class ToolFuzzer:
    """Orchestrates fuzzing of MCP tools."""

    def __init__(self):
        self.strategies = ToolStrategies()

    def fuzz_tool(
        self, tool: Dict[str, Any], runs: int = 10, phase: str = "aggressive"
    ) -> List[Dict[str, Any]]:
        """Fuzz a tool by calling it with arguments based on the specified phase."""
        results = []
        tool_name = tool.get("name", "unknown")
        # Minimal INFO-level signal for tests and user feedback
        logging.info(f"Starting fuzzing for tool: {tool_name}")

        for i in range(runs):
            try:
                # Generate fuzz arguments using the strategy with phase
                args = self.strategies.fuzz_tool_arguments(tool, phase=phase)

                # Apply safety filtering
                if not is_safe_tool_call(tool_name, args):
                    safety_filter.log_blocked_operation(
                        tool_name, args, "Dangerous operation detected"
                    )
                    results.append(
                        {
                            "tool_name": tool_name,
                            "run": i + 1,
                            "args": args,
                            "success": False,
                            "safety_blocked": True,
                            "safety_reason": "Dangerous operation blocked",
                        }
                    )
                    continue

                # Sanitize arguments
                sanitized_tool_name, sanitized_args = sanitize_tool_call(
                    tool_name, args
                )

                # Keep high-level progress at DEBUG to avoid noisy INFO
                logging.debug(
                    f"Fuzzing {tool_name} ({phase} phase, run {i + 1}/{runs}) "
                    f"with args: {sanitized_args}"
                )

                results.append(
                    {
                        "tool_name": tool_name,
                        "run": i + 1,
                        "args": sanitized_args,
                        "original_args": args if args != sanitized_args else None,
                        "success": True,
                        "safety_sanitized": args != sanitized_args,
                    }
                )

            except Exception as e:
                tool_name = tool.get("name", "unknown")
                logging.warning(f"Exception during fuzzing {tool_name}: {e}")
                results.append(
                    {
                        "tool_name": tool_name,
                        "run": i + 1,
                        "args": args if "args" in locals() else None,
                        "exception": str(e),
                        "success": False,
                    }
                )

        return results

    def fuzz_tool_both_phases(
        self, tool: Dict[str, Any], runs_per_phase: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz a tool in both realistic and aggressive phases."""
        results = {}
        tool_name = tool.get("name", "unknown")

        logging.info(f"Running two-phase fuzzing for tool: {tool_name}")

        # Phase 1: Realistic fuzzing
        logging.info(f"Phase 1: Realistic fuzzing for {tool_name}")
        results["realistic"] = self.fuzz_tool(
            tool, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        logging.info(f"Phase 2: Aggressive fuzzing for {tool_name}")
        results["aggressive"] = self.fuzz_tool(
            tool, runs=runs_per_phase, phase="aggressive"
        )

        return results

    def fuzz_tools(
        self,
        tools: List[Dict[str, Any]],
        runs_per_tool: int = 10,
        phase: str = "aggressive",
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz multiple tools."""
        all_results = {}

        if tools is None:
            return all_results

        for tool in tools:
            tool_name = tool.get("name", "unknown")
            logging.info(f"Starting to fuzz tool: {tool_name}")

            try:
                results = self.fuzz_tool(tool, runs_per_tool, phase)
                all_results[tool_name] = results

                # Calculate statistics
                successful = len([r for r in results if r.get("success", False)])
                exceptions = len([r for r in results if not r.get("success", False)])

                logging.info(
                    "Completed fuzzing %s: %d successful, %d exceptions out of %d runs",
                    tool_name,
                    successful,
                    exceptions,
                    runs_per_tool,
                )

            except Exception as e:
                logging.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results
