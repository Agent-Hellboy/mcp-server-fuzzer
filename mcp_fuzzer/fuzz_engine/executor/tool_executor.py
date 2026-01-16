#!/usr/bin/env python3
"""
Tool Executor

This module contains execution orchestration logic for tool fuzzing.
"""

import asyncio
import logging
from typing import Any

from ...safety_system.safety import SafetyFilter, SafetyProvider
from .async_executor import AsyncFuzzExecutor
from ..mutators import ToolMutator
from ..fuzzerreporter import ResultBuilder, ResultCollector


class ToolExecutor:
    """Orchestrates tool fuzzing execution."""

    def __init__(
        self,
        mutator: ToolMutator | None = None,
        executor: AsyncFuzzExecutor | None = None,
        result_builder: ResultBuilder | None = None,
        safety_system: SafetyProvider | None = None,
        enable_safety: bool = True,
        max_concurrency: int = 5,
    ):
        """
        Initialize the tool executor.

        Args:
            mutator: Tool mutator for generating fuzzed arguments
            executor: Async executor for running operations
            result_builder: Result builder for creating standardized results
            safety_system: Safety system for filtering operations
            enable_safety: Whether to enable safety system
            max_concurrency: Maximum number of concurrent operations
        """
        self.mutator = mutator or ToolMutator()
        self.executor = executor or AsyncFuzzExecutor(max_concurrency=max_concurrency)
        self.result_builder = result_builder or ResultBuilder()
        self.collector = ResultCollector()
        if not enable_safety:
            self.safety_system = None
        else:
            self.safety_system = safety_system or SafetyFilter()
        self._logger = logging.getLogger(__name__)

    async def execute(
        self, tool: dict[str, Any], runs: int = 10, phase: str = "aggressive"
    ) -> list[dict[str, Any]]:
        """
        Execute fuzzing runs for a tool.

        Args:
            tool: Tool definition
            runs: Number of fuzzing runs
            phase: Fuzzing phase (realistic or aggressive)

        Returns:
            List of fuzzing results
        """
        tool_name = tool.get("name", "unknown")
        self._logger.info(f"Starting fuzzing for tool: {tool_name}")

        operations = [
            (self._execute_single_run, [tool, i, phase], {}) for i in range(runs)
        ]

        # Execute all operations in parallel with controlled concurrency
        batch_results = await self.executor.execute_batch(operations)

        results = self.collector.collect_results(batch_results)
        for error in batch_results.get("errors", []):
            self._logger.warning(f"Error during fuzzing {tool_name}: {error}")
        return results

    async def _execute_single_run(
        self, tool: dict[str, Any], run_index: int, phase: str
    ) -> dict[str, Any] | None:
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
            # Generate fuzz arguments using mutator
            args = await self.mutator.mutate(tool, phase)

            safety_sanitized = False
            sanitized_args = args

            if self.safety_system:
                if self.safety_system.should_skip_tool_call(tool_name, args):
                    self.safety_system.log_blocked_operation(
                        tool_name, args, "Dangerous operation detected"
                    )
                    return self.result_builder.build_tool_result(
                        tool_name=tool_name,
                        run_index=run_index,
                        args=args,
                        success=False,
                        safety_blocked=True,
                        safety_reason="Dangerous operation blocked",
                    )

                # Sanitize arguments
                sanitized_args = self.safety_system.sanitize_tool_arguments(
                    tool_name, args
                )
                safety_sanitized = sanitized_args != args

            # Keep high-level progress at DEBUG to avoid noisy INFO
            self._logger.debug(
                f"Fuzzing {tool_name} ({phase} phase, run {run_index + 1}) "
                f"with args: {sanitized_args}"
            )

            return self.result_builder.build_tool_result(
                tool_name=tool_name,
                run_index=run_index,
                args=sanitized_args,
                original_args=(args if args != sanitized_args else None),
                success=True,
                safety_sanitized=safety_sanitized,
            )

        except Exception as e:
            self._logger.warning(f"Exception during fuzzing {tool_name}: {e}")
            return self.result_builder.build_tool_result(
                tool_name=tool_name,
                run_index=run_index,
                args=args if "args" in locals() else None,
                success=False,
                exception=str(e),
            )

    async def execute_both_phases(
        self, tool: dict[str, Any], runs_per_phase: int = 5
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Execute fuzzing in both realistic and aggressive phases.

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
        results["realistic"] = await self.execute(
            tool, runs=runs_per_phase, phase="realistic"
        )

        # Phase 2: Aggressive fuzzing
        self._logger.info(f"Phase 2: Aggressive fuzzing for {tool_name}")
        results["aggressive"] = await self.execute(
            tool, runs=runs_per_phase, phase="aggressive"
        )

        return results

    async def execute_multiple(
        self,
        tools: list[dict[str, Any]],
        runs_per_tool: int = 10,
        phase: str = "aggressive",
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Execute fuzzing for multiple tools asynchronously.

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
        tasks = [
            (
                tool.get("name", "unknown"),
                asyncio.create_task(
                    self._execute_single_tool(tool, runs_per_tool, phase)
                ),
            )
            for tool in tools
        ]

        # Wait for all tasks to complete
        for tool_name, task in tasks:
            try:
                results = await task
                all_results[tool_name] = results
            except Exception as e:
                self._logger.error(f"Failed to fuzz tool {tool_name}: {e}")
                all_results[tool_name] = [{"error": str(e)}]

        return all_results

    async def _execute_single_tool(
        self,
        tool: dict[str, Any],
        runs_per_tool: int,
        phase: str,
    ) -> list[dict[str, Any]]:
        """
        Execute fuzzing for a single tool and log statistics.

        Args:
            tool: Tool definition
            runs_per_tool: Number of runs
            phase: Fuzzing phase

        Returns:
            List of fuzzing results
        """
        tool_name = tool.get("name", "unknown")
        self._logger.info(f"Starting to fuzz tool: {tool_name}")

        results = await self.execute(tool, runs_per_tool, phase)

        # Calculate statistics
        successful = sum(1 for r in results if r.get("success", False))
        exceptions = len(results) - successful

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
