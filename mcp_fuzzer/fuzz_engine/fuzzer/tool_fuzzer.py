#!/usr/bin/env python3
"""
Tool Fuzzer

This module contains the orchestration logic for fuzzing MCP tools.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from ...safety_system.safety import (
    safety_filter,
    is_safe_tool_call,
    sanitize_tool_call,
)
from ..executor import AsyncFuzzExecutor
from ..strategy import ToolStrategies


class ToolFuzzer:
    """Orchestrates fuzzing of MCP tools."""

    def __init__(self, max_concurrency: int = 5):
        """
        Initialize the tool fuzzer.

        Args:
            max_concurrency: Maximum number of concurrent fuzzing operations
        """
        self.strategies = ToolStrategies()
        self.executor = AsyncFuzzExecutor(max_concurrency=max_concurrency)
        self._logger = logging.getLogger(__name__)

    async def fuzz_tool(
        self, tool: Dict[str, Any], runs: int = 10, phase: str = "aggressive"
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a tool by calling it with arguments based on the specified phase.

        Args:
            tool: Tool definition
            runs: Number of fuzzing runs
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            List of fuzzing results
        """
        results = []
        tool_name = tool.get("name", "unknown")
        # Minimal INFO-level signal for tests and user feedback
        self._logger.info(f"Starting fuzzing for tool: {tool_name}")

        # Create a list of operations to execute
        operations = []
        for i in range(runs):
            operations.append((self._fuzz_tool_single_run, [tool, i, phase], {}))

        # Execute all operations in parallel with controlled concurrency
        batch_results = await self.executor.execute_batch(operations)

        # Process results
        for result in batch_results["results"]:
            if result is not None:
                results.append(result)

        # Process errors
        for error in batch_results["errors"]:
            self._logger.warning(f"Error during fuzzing {tool_name}: {error}")
            results.append(
                {
                    "tool_name": tool_name,
                    "exception": str(error),
                    "success": False,
                }
            )

        return results

    async def _fuzz_tool_single_run(
        self, tool: Dict[str, Any], run_index: int, phase: str
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a single fuzzing run for a tool.

        Args:
            tool: Tool definition
            run_index: Run index (0-based)
            phase: Fuzzing phase

        Returns:
            Fuzzing result or None if error
        """
        tool_name = tool.get("name", "unknown")

        try:
            # Generate fuzz arguments using the strategy with phase
            args = await self.strategies.fuzz_tool_arguments(tool, phase=phase)

            # Apply safety filtering
            if not is_safe_tool_call(tool_name, args):
                safety_filter.log_blocked_operation(
                    tool_name, args, "Dangerous operation detected"
                )
                return {
                    "tool_name": tool_name,
                    "run": run_index + 1,
                    "args": args,
                    "success": False,
                    "safety_blocked": True,
                    "safety_reason": "Dangerous operation blocked",
                }

            # Sanitize arguments
            sanitized_tool_name, sanitized_args = sanitize_tool_call(tool_name, args)

            # Keep high-level progress at DEBUG to avoid noisy INFO
            self._logger.debug(
                f"Fuzzing {tool_name} ({phase} phase, run {run_index + 1}) "
                f"with args: {sanitized_args}"
            )

            return {
                "tool_name": tool_name,
                "run": run_index + 1,
                "args": sanitized_args,
                "original_args": (args if args != sanitized_args else None),
                "success": True,
                "safety_sanitized": args != sanitized_args,
            }

        except Exception as e:
            self._logger.warning(f"Exception during fuzzing {tool_name}: {e}")
            return {
                "tool_name": tool_name,
                "run": run_index + 1,
                "args": args if "args" in locals() else None,
                "exception": str(e),
                "success": False,
            }

    async def fuzz_tool_both_phases(
        self, tool: Dict[str, Any], runs_per_phase: int = 5
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fuzz a tool in both realistic and aggressive phases.

        Args:
            tool: Tool definition
            runs_per_phase: Number of runs per phase

        Returns:
            Dictionary with results for each phase
        """
        results = {}
        tool_name = tool.get("name", "unknown")

        self._logger.info(f"Running two-phase fuzzing for tool: {tool_name}")

        # Phase 1: Realistic fuzzing
        self._logger.info(f"Phase 1: Realistic fuzzing for {tool_name}")
        results["realistic"] = await self.fuzz_tool(
            tool, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        self._logger.info(f"Phase 2: Aggressive fuzzing for {tool_name}")
        results["aggressive"] = await self.fuzz_tool(
            tool, runs=runs_per_phase, phase="aggressive"
        )

        return results

    async def fuzz_tools(
        self,
        tools: List[Dict[str, Any]],
        runs_per_tool: int = 10,
        phase: str = "aggressive",
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fuzz multiple tools asynchronously.

        Args:
            tools: List of tool definitions
            runs_per_tool: Number of runs per tool
            phase: Fuzzing phase

        Returns:
            Dictionary with results for each tool
        """
        all_results = {}

        if tools is None:
            return all_results

        # Create tasks for each tool
        tasks = []
        for tool in tools:
            task = asyncio.create_task(
                self._fuzz_single_tool(tool, runs_per_tool, phase)
            )
            tasks.append((tool.get("name", "unknown"), task))

        # Wait for all tasks to complete
        for tool_name, task in tasks:
            try:
                results = await task
                all_results[tool_name] = results
            except Exception as e:
                self._logger.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results

    async def _fuzz_single_tool(
        self,
        tool: Dict[str, Any],
        runs_per_tool: int,
        phase: str,
    ) -> List[Dict[str, Any]]:
        """
        Fuzz a single tool and log statistics.

        Args:
            tool: Tool definition
            runs_per_tool: Number of runs
            phase: Fuzzing phase

        Returns:
            List of fuzzing results
        """
        tool_name = tool.get("name", "unknown")
        self._logger.info(f"Starting to fuzz tool: {tool_name}")

        results = await self.fuzz_tool(tool, runs_per_tool, phase)

        # Calculate statistics
        successful = len([r for r in results if r.get("success", False)])
        exceptions = len([r for r in results if not r.get("success", False)])

        self._logger.info(
            "Completed fuzzing %s: %d successful, %d exceptions out of %d runs",
            tool_name,
            successful,
            exceptions,
            runs_per_tool,
        )

        return results

    async def shutdown(self) -> None:
        """Shutdown the executor and clean up resources."""
        await self.executor.shutdown()
