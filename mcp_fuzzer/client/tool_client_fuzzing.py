"""Fuzz orchestration, concurrency, and multi-tool sessions for ToolClient."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..config.constants import (
    DEFAULT_FORCE_KILL_TIMEOUT,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_TOOL_RUNS,
)
from ..types import ErrorType, TimeoutScope

from .tool_client_results import build_phase_error, build_tool_run_result


class ToolClientFuzzingMixin:
    """Bounded concurrent fuzz runs and multi-tool session orchestration."""

    _logger: logging.Logger
    max_concurrency: int
    tool_mutator: Any

    async def _run_bounded(self, count: int, factory) -> list[Any]:
        """Run up to ``count`` async factories with concurrency limiting."""
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _limited(index: int):
            async with semaphore:
                return await factory(index)

        return list(await asyncio.gather(*(_limited(i) for i in range(count))))

    async def fuzz_tool(
        self,
        tool: dict[str, Any],
        runs: int = DEFAULT_TOOL_RUNS,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fuzz a tool by calling it with random/edge-case arguments."""
        tool_name = tool.get("name", "unknown")

        async def _one_run(_index: int) -> dict[str, Any]:
            try:
                args = await self.tool_mutator.mutate(tool)
                self._logger.debug(
                    "Fuzzing %s (run %d/%d)", tool_name, _index + 1, runs
                )
                return await self._execute_tool_call(
                    tool_name,
                    args,
                    label=f"tool:{tool_name}",
                    tool_timeout=tool_timeout,
                )
            except Exception as e:
                self._logger.warning("Exception during fuzzing %s: %s", tool_name, e)
                return build_tool_run_result(
                    args=None,
                    label=f"tool:{tool_name}",
                    success=False,
                    safety_blocked=False,
                    safety_sanitized=False,
                    error=ErrorType.TOOL_MUTATION_FAILED,
                    exception=str(e),
                )

        return await self._run_bounded(runs, _one_run)

    async def _fuzz_single_tool_with_timeout(
        self,
        tool: dict[str, Any],
        runs_per_tool: int,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        tool_name = tool.get("name", "unknown")
        max_tool_time = DEFAULT_MAX_TOOL_TIME

        try:
            tool_task = asyncio.create_task(
                self.fuzz_tool(tool, runs_per_tool, tool_timeout=tool_timeout),
                name=f"fuzz_tool_{tool_name}",
            )

            try:
                return await asyncio.wait_for(tool_task, timeout=max_tool_time)
            except asyncio.TimeoutError:
                self._logger.warning("Tool %s took too long, cancelling", tool_name)
                tool_task.cancel()
                try:
                    await asyncio.wait_for(
                        tool_task, timeout=DEFAULT_FORCE_KILL_TIMEOUT
                    )
                except (
                    asyncio.CancelledError,
                    TimeoutError,
                    asyncio.TimeoutError,
                ):
                    pass
                return [
                    build_tool_run_result(
                        args=None,
                        label=f"tool:{tool_name}",
                        success=False,
                        safety_blocked=False,
                        safety_sanitized=False,
                        error=ErrorType.TOOL_TIMEOUT,
                        exception="Tool fuzzing timed out",
                        timeout_scope=TimeoutScope.SESSION,
                    )
                ]
        except Exception as e:
            self._logger.error("Failed to fuzz tool %s: %s", tool_name, e)
            return [
                build_tool_run_result(
                    args=None,
                    label=f"tool:{tool_name}",
                    success=False,
                    safety_blocked=False,
                    safety_sanitized=False,
                    error=ErrorType.PHASE_EXECUTION_FAILED,
                    exception=str(e),
                )
            ]

    async def fuzz_all_tools(
        self,
        runs_per_tool: int = DEFAULT_TOOL_RUNS,
        tool_timeout: float | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Fuzz all tools from the server."""
        self._logger.debug(
            "fuzz_all_tools called with runs_per_tool=%s, tool_timeout=%s",
            runs_per_tool,
            tool_timeout,
        )
        self._logger.info("Fetching tools from server...")
        tools = await self._get_tools_from_server()
        self._logger.debug(
            "_get_tools_from_server returned %s tools",
            len(tools) if tools else 0,
        )
        if not tools:
            self._logger.warning("No tools available for fuzzing")
            return {}

        all_results = {}
        start_time = asyncio.get_event_loop().time()
        max_total_time = DEFAULT_MAX_TOTAL_FUZZING_TIME

        for i, tool in enumerate(tools):
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > max_total_time:
                self._logger.warning(
                    "Fuzzing session taking too long (%.1fs), stopping early",
                    elapsed,
                )
                break

            tool_name = tool.get("name", "unknown")
            self._logger.info(
                "Starting to fuzz tool: %s (%d/%d)",
                tool_name,
                i + 1,
                len(tools),
            )

            results = await self._fuzz_single_tool_with_timeout(
                tool, runs_per_tool, tool_timeout
            )
            tool_entry: dict[str, Any] = {"runs": results}
            self._attach_schema_checks(tool_name, tool_entry)
            all_results[tool_name] = tool_entry

            exceptions = [r for r in results if "exception" in r]
            self._logger.info(
                "Completed fuzzing %s: %d exceptions out of %d runs",
                tool_name,
                len(exceptions),
                runs_per_tool,
            )

        return all_results

    def _print_phase_report(
        self, tool_name: str, phase: str, results: list[dict[str, Any]]
    ):
        from ..reports import FuzzerReporter

        if not hasattr(self, "reporter") or not isinstance(
            self.reporter, FuzzerReporter
        ):
            return

        successful = len([r for r in results if r.get("success", False)])
        total = len(results)
        self.reporter.console.print(
            f"  {phase.title()} phase: {successful}/{total} successful"
        )

    async def _run_tool_phase(
        self,
        tool: dict[str, Any],
        *,
        phase_name: str,
        mutate_phase: str | None,
        runs: int,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        tool_name = tool.get("name", "unknown")
        self._logger.info("%s phase: %s", phase_name.title(), tool_name)

        async def _one_run(_index: int) -> dict[str, Any]:
            try:
                if mutate_phase is None:
                    args = await self.tool_mutator.mutate(tool)
                else:
                    args = await self.tool_mutator.mutate(tool, phase=mutate_phase)
                return await self._execute_tool_call(
                    tool_name,
                    args,
                    label=f"tool:{tool_name}",
                    tool_timeout=tool_timeout,
                )
            except Exception as e:
                self._logger.warning(
                    "Exception during %s phase fuzzing %s: %s",
                    phase_name,
                    tool_name,
                    e,
                )
                return build_tool_run_result(
                    args=None,
                    label=f"tool:{tool_name}",
                    success=False,
                    safety_blocked=False,
                    safety_sanitized=False,
                    error=ErrorType.PHASE_EXECUTION_FAILED,
                    exception=str(e),
                )

        return await self._run_bounded(runs, _one_run)

    async def fuzz_tool_both_phases(
        self,
        tool: dict[str, Any],
        runs_per_phase: int = 5,
        tool_timeout: float | None = None,
    ) -> dict[str, Any]:
        """Fuzz a specific tool in both realistic and aggressive phases."""
        tool_name = tool.get("name", "unknown")
        self._logger.info("Starting two-phase fuzzing for tool: %s", tool_name)

        try:
            realistic_processed = await self._run_tool_phase(
                tool,
                phase_name="realistic",
                mutate_phase="realistic",
                runs=runs_per_phase,
                tool_timeout=tool_timeout,
            )
            aggressive_processed = await self._run_tool_phase(
                tool,
                phase_name="aggressive",
                mutate_phase=None,
                runs=runs_per_phase,
                tool_timeout=tool_timeout,
            )

            return {
                "realistic": realistic_processed,
                "aggressive": aggressive_processed,
            }

        except Exception as e:
            self._logger.error(
                "Error during two-phase fuzzing of tool %s: %s", tool_name, e
            )
            return build_phase_error(tool_name, str(e))

    async def _fuzz_single_tool_both_phases(
        self,
        tool: dict[str, Any],
        runs_per_phase: int,
        tool_timeout: float | None = None,
    ) -> dict[str, Any]:
        tool_name = tool.get("name", "unknown")
        self._logger.info("Two-phase fuzzing tool: %s", tool_name)

        try:
            phase_results = await self.fuzz_tool_both_phases(
                tool,
                runs_per_phase,
                tool_timeout=tool_timeout,
            )

            if "error" in phase_results:
                self._logger.error(
                    "Error in two-phase fuzzing %s: %s",
                    tool_name,
                    phase_results["error"],
                )
                return phase_results

            return phase_results

        except Exception as e:
            self._logger.error("Error in two-phase fuzzing %s: %s", tool_name, e)
            return build_phase_error(tool_name, str(e))

    async def fuzz_all_tools_both_phases(
        self,
        runs_per_phase: int = 5,
        tool_timeout: float | None = None,
    ) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Fuzz all tools in both realistic and aggressive phases."""
        self._logger.info("Starting Two-Phase Tool Fuzzing")

        try:
            tools = await self._get_tools_from_server()
            if not tools:
                self._logger.warning("No tools available for fuzzing")
                return {}

            all_results = {}

            for tool in tools:
                tool_name = tool.get("name", "unknown")
                phase_results = await self._fuzz_single_tool_both_phases(
                    tool,
                    runs_per_phase,
                    tool_timeout=tool_timeout,
                )
                self._attach_schema_checks(tool_name, phase_results)
                all_results[tool_name] = phase_results

            return all_results

        except Exception as e:
            self._logger.error("Failed to fuzz all tools (two-phase): %s", e)
            return {}
