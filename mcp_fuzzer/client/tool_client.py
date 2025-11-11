#!/usr/bin/env python3
"""
Tool Client Module

This module provides functionality for fuzzing MCP tools.
"""

import asyncio
import logging
from typing import Any

from ..auth import AuthManager
from ..fuzz_engine.fuzzer import ToolFuzzer
from ..safety_system.safety import SafetyFilter, SafetyProvider
from ..config import (
    DEFAULT_TOOL_RUNS,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_FORCE_KILL_TIMEOUT,
)

class ToolClient:
    """Client for fuzzing MCP tools."""

    def __init__(
        self,
        transport,
        auth_manager: AuthManager | None = None,
        safety_system: SafetyProvider | None = None,
        max_concurrency: int = 5,
        enable_safety: bool = True,
    ):
        """
        Initialize the tool client.

        Args:
            transport: Transport protocol for server communication
            auth_manager: Authentication manager for tool authentication
            safety_system: Safety system for filtering operations
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self.auth_manager = auth_manager or AuthManager()
        self.enable_safety = enable_safety
        if not enable_safety:
            self.safety_system = None
        else:
            self.safety_system = safety_system or SafetyFilter()
        self.tool_fuzzer = ToolFuzzer(
            max_concurrency=max_concurrency,
            safety_system=self.safety_system,
            enable_safety=self.enable_safety,
        )
        self._logger = logging.getLogger(__name__)

    async def _get_tools_from_server(self) -> list[dict[str, Any]]:
        """Get tools from the server.

        Returns:
            List of tool definitions or empty list if failed.
        """
        try:
            tools = await self.transport.get_tools()
            if not tools:
                self._logger.warning("Server returned an empty list of tools.")
                return []
            self._logger.info(f"Found {len(tools)} tools to fuzz")
            return tools
        except Exception as e:
            self._logger.error(f"Failed to get tools from server: {e}")
            return []

    async def _fuzz_single_tool_with_timeout(
        self,
        tool: dict[str, Any],
        runs_per_tool: int,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fuzz a single tool with timeout handling.

        Args:
            tool: Tool definition to fuzz
            runs_per_tool: Number of runs per tool
            tool_timeout: Optional timeout for tool fuzzing

        Returns:
            List of fuzzing results
        """
        tool_name = tool.get("name", "unknown")
        max_tool_time = DEFAULT_MAX_TOOL_TIME  # 1 minute max per tool

        try:
            tool_task = asyncio.create_task(
                self.fuzz_tool(tool, runs_per_tool, tool_timeout=tool_timeout),
                name=f"fuzz_tool_{tool_name}"
            )

            try:
                return await asyncio.wait_for(tool_task, timeout=max_tool_time)
            except asyncio.TimeoutError:
                self._logger.warning(f"Tool {tool_name} took too long, cancelling")
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
                    {
                        "error": "tool_timeout",
                        "exception": "Tool fuzzing timed out",
                    }
                ]
        except Exception as e:
            self._logger.error(f"Failed to fuzz tool {tool_name}: {e}")
            return [{"error": str(e)}]

    async def fuzz_tool(
        self,
        tool: dict[str, Any],
        runs: int = DEFAULT_TOOL_RUNS,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        """Fuzz a tool by calling it with random/edge-case arguments."""
        results = []
        tool_name = tool.get("name", "unknown")

        for i in range(runs):
            try:
                # Generate fuzz arguments using the fuzzer
                fuzz_list = await self.tool_fuzzer.fuzz_tool(tool, 1)
                if not fuzz_list:
                    self._logger.warning("Fuzzer returned no args for %s", tool_name)
                    continue
                fuzz_result = fuzz_list[0]  # Get single result
                args = fuzz_result["args"]

                # Check safety before proceeding
                if self.safety_system and self.safety_system.should_skip_tool_call(
                    tool_name, args
                ):
                    self._logger.warning(
                        "Safety system blocked tool call for %s", tool_name
                    )
                    results.append(
                        {
                            "args": args,
                            "exception": "safety_blocked",
                            "safety_blocked": True,
                            "safety_sanitized": False,
                        }
                    )
                    continue

                # Sanitize arguments if safety system is enabled
                sanitized_args = args
                safety_sanitized = False
                if self.safety_system:
                    sanitized_args = self.safety_system.sanitize_tool_arguments(
                        tool_name, args
                    )
                    safety_sanitized = sanitized_args != args

                # Get authentication for this tool
                auth_params = self.auth_manager.get_auth_params_for_tool(tool_name)

                # Merge auth params only into the call payload; never persist secrets
                args_for_call = {**sanitized_args}
                if auth_params:
                    args_for_call.update(auth_params)

                # High-level run progress at DEBUG to avoid noise
                self._logger.debug("Fuzzing %s (run %d/%d)", tool_name, i + 1, runs)

                # Call the tool with the generated arguments
                try:
                    result = await self.transport.call_tool(
                        tool_name, args_for_call
                    )
                    results.append(
                        {
                            "args": sanitized_args,
                            "result": result,
                            "safety_blocked": False,
                            "safety_sanitized": safety_sanitized,
                            "success": True,
                        }
                    )
                except Exception as e:
                    self._logger.warning("Exception calling tool %s: %s", tool_name, e)
                    results.append(
                        {
                            "args": sanitized_args,
                            "exception": str(e),
                            "safety_blocked": False,
                            "safety_sanitized": safety_sanitized,
                            "success": False,
                        }
                    )

            except Exception as e:
                self._logger.warning("Exception during fuzzing %s: %s", tool_name, e)
                results.append(
                    {
                        "args": None,
                        "exception": str(e),
                        "safety_blocked": False,
                        "safety_sanitized": False,
                        "success": False,
                    }
                )

        return results

    async def fuzz_all_tools(
        self,
        runs_per_tool: int = DEFAULT_TOOL_RUNS,
        tool_timeout: float | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Fuzz all tools from the server."""
        tools = await self._get_tools_from_server()
        if not tools:
            return {}

        all_results = {}
        start_time = asyncio.get_event_loop().time()
        # 5 minutes max for entire fuzzing session
        max_total_time = DEFAULT_MAX_TOTAL_FUZZING_TIME

        for i, tool in enumerate(tools):
            # Check if we're taking too long overall
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > max_total_time:
                self._logger.warning(
                    f"Fuzzing session taking too long ({elapsed:.1f}s), stopping early"
                )
                break

            tool_name = tool.get("name", "unknown")
            self._logger.info(
                f"Starting to fuzz tool: {tool_name} ({i + 1}/{len(tools)})"
            )

            results = await self._fuzz_single_tool_with_timeout(
                tool, runs_per_tool, tool_timeout
            )
            all_results[tool_name] = results

            # Calculate statistics
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
        """Print phase report statistics."""
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

    async def _fuzz_single_tool_both_phases(
        self, tool: dict[str, Any], runs_per_phase: int
    ) -> dict[str, Any]:
        """Fuzz a single tool in both phases and report results."""
        tool_name = tool.get("name", "unknown")

        self._logger.info(f"Two-phase fuzzing tool: {tool_name}")

        try:
            # Run both phases for this tool
            phase_results = await self.fuzz_tool_both_phases(tool, runs_per_phase)

            # Check if the result is an error
            if "error" in phase_results:
                self._logger.error(
                    f"Error in two-phase fuzzing {tool_name}: {phase_results['error']}"
                )
                return {"error": phase_results["error"]}

            return phase_results

        except Exception as e:
            self._logger.error(f"Error in two-phase fuzzing {tool_name}: {e}")
            return {"error": str(e)}

    async def _process_fuzz_results(
        self,
        tool_name: str,
        fuzz_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Process fuzz results with safety checks and tool calls.
        
        Args:
            tool_name: Name of the tool being fuzzed
            fuzz_results: List of fuzz results from the fuzzer
            
        Returns:
            List of processed results with tool call outcomes
        """
        processed = []
        for fuzz_result in fuzz_results:
            args = fuzz_result["args"]

            # Skip if safety system blocks this call
            if self.safety_system and self.safety_system.should_skip_tool_call(
                tool_name, args
            ):
                processed.append(
                    {
                        "args": args,
                        "exception": "safety_blocked",
                        "safety_blocked": True,
                        "safety_sanitized": False,
                        "success": False,
                    }
                )
                continue

            # Sanitize arguments if needed
            sanitized_args = args
            safety_sanitized = False
            if self.safety_system:
                sanitized_args = self.safety_system.sanitize_tool_arguments(
                    tool_name, args
                )
                safety_sanitized = sanitized_args != args

            # Get authentication for this tool
            auth_params = self.auth_manager.get_auth_params_for_tool(tool_name)

            # Merge auth params only into call payload
            args_for_call = {**sanitized_args}
            if auth_params:
                args_for_call.update(auth_params)

            # Call the tool with the generated arguments
            try:
                result = await self.transport.call_tool(tool_name, args_for_call)
                processed.append(
                    {
                        "args": sanitized_args,
                        "result": result,
                        "safety_blocked": False,
                        "safety_sanitized": safety_sanitized,
                        "success": True,
                    }
                )
            except Exception as e:
                processed.append(
                    {
                        "args": sanitized_args,
                        "exception": str(e),
                        "safety_blocked": False,
                        "safety_sanitized": safety_sanitized,
                        "success": False,
                    }
                )

        return processed

    async def fuzz_tool_both_phases(
        self, tool: dict[str, Any], runs_per_phase: int = 5
    ) -> dict[str, list[dict[str, Any]]]:
        """Fuzz a specific tool in both realistic and aggressive phases."""
        tool_name = tool.get("name", "unknown")
        self._logger.info(f"Starting two-phase fuzzing for tool: {tool_name}")

        try:
            # Phase 1: Realistic fuzzing
            self._logger.info(f"Phase 1 (Realistic): {tool_name}")
            realistic_results = await self.tool_fuzzer.fuzz_tool(
                tool, runs_per_phase, phase="realistic"
            )
            realistic_processed = await self._process_fuzz_results(
                tool_name, realistic_results
            )

            # Phase 2: Aggressive fuzzing
            self._logger.info(f"Phase 2 (Aggressive): {tool_name}")
            aggressive_results = await self.tool_fuzzer.fuzz_tool(
                tool, runs_per_phase, phase="aggressive"
            )
            aggressive_processed = await self._process_fuzz_results(
                tool_name, aggressive_results
            )

            return {
                "realistic": realistic_processed,
                "aggressive": aggressive_processed,
            }

        except Exception as e:
            self._logger.error(
                f"Error during two-phase fuzzing of tool {tool_name}: {e}"
            )
            return {"error": str(e)}

    async def fuzz_all_tools_both_phases(
        self, runs_per_phase: int = 5
    ) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Fuzz all tools in both realistic and aggressive phases."""
        # Use reporter for output instead of console
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
                    tool, runs_per_phase
                )
                all_results[tool_name] = phase_results

            return all_results

        except Exception as e:
            self._logger.error(f"Failed to fuzz all tools (two-phase): {e}")
            return {}

    async def shutdown(self):
        """Shutdown the tool fuzzer."""
        await self.tool_fuzzer.shutdown()
