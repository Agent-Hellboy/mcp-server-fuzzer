#!/usr/bin/env python3
"""
Tool Client Module

This module provides functionality for fuzzing MCP tools.
"""

import asyncio
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..auth import AuthManager
from .. import spec_guard
from ..fuzz_engine.mutators import ToolMutator
from ..fuzz_engine.mutators.context import FuzzerContext
from ..fuzz_engine.mutators.sequence import SequenceMutator
from ..fuzz_engine.executor.sequence_executor import SequenceExecutor
from ..safety_system.safety import SafetyFilter, SafetyProvider
from ..security_mode import SecurityModeEngine
from ..security_mode.policy import SecurityPolicy
from ..security_mode.oracles import (
    FilesystemSideEffectOracle,
    NetworkSideEffectOracle,
    ProcessSideEffectOracle,
)

# Import constants directly from config (constants are values, not behavior)
from ..config.core.constants import (
    DEFAULT_TOOL_RUNS,
    DEFAULT_MAX_TOOL_TIME,
    DEFAULT_MAX_TOTAL_FUZZING_TIME,
    DEFAULT_FORCE_KILL_TIMEOUT,
)
from ..transport.interfaces import JsonRpcAdapter


@dataclass(frozen=True)
class SecurityCallOutcome:
    result: Any | None
    exception: Exception | None
    oracle_findings: list[dict[str, Any]]
    side_effects: list[dict[str, Any]]
    policy_violations: list[dict[str, Any]]
    semantic_mismatch: dict[str, Any] | None


class ToolClient:
    """Client for fuzzing MCP tools."""

    def __init__(
        self,
        transport,
        auth_manager: AuthManager | None = None,
        safety_system: SafetyProvider | None = None,
        max_concurrency: int = 5,
        enable_safety: bool = True,
        corpus_root: Path | None = None,
        havoc_mode: bool = False,
        security_policy: SecurityPolicy | None = None,
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
        self._rpc = JsonRpcAdapter(transport)
        self.auth_manager = auth_manager or AuthManager()
        self.enable_safety = enable_safety
        if not enable_safety:
            self.safety_system = None
        else:
            self.safety_system = safety_system or SafetyFilter()
        self.tool_mutator = ToolMutator(
            corpus_dir=corpus_root, havoc_mode=havoc_mode
        )
        self._sequence_context = FuzzerContext(corpus_dir=corpus_root)
        self._sequence_executor = SequenceExecutor(self._rpc)
        self._sequence_runs: list[dict[str, Any]] = []
        self._available_tools: list[dict[str, Any]] = []
        self._logger = logging.getLogger(__name__)
        self._tool_schema_checks: dict[str, list[dict[str, Any]]] = {}
        self._security_policy = security_policy
        self._security_oracles = []
        if security_policy and security_policy.enabled:
            self._security_oracles = [
                ProcessSideEffectOracle(security_policy),
                FilesystemSideEffectOracle(security_policy),
                NetworkSideEffectOracle(security_policy),
            ]
        self._security_engine = (
            SecurityModeEngine(security_policy)
            if security_policy and security_policy.enabled
            else None
        )
        self._auth_probe_done: set[str] = set()
        self._auth_probe_findings: dict[str, list[dict[str, Any]]] = {}
        self._session_replay_checked: set[str] = set()
        self._last_session_id: str | None = None

    async def _get_tools_from_server(self) -> list[dict[str, Any]]:
        """Get tools from the server.

        Returns:
            List of tool definitions or empty list if failed.
        """
        try:
            tools = await self._rpc.get_tools()
            if not tools:
                self._logger.warning("Server returned an empty list of tools.")
                return []
            self._logger.info(f"Found {len(tools)} tools to fuzz")
            self._tool_schema_checks.clear()
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                checks = spec_guard.check_tool_schema_fields(tool)
                if checks:
                    self._tool_schema_checks[tool_name] = checks
            self._logger.debug(f"Tools: {tools}")
            self._available_tools = tools
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
                name=f"fuzz_tool_{tool_name}",
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
                # Generate fuzz arguments using the mutator
                args = await self.tool_mutator.mutate(tool)

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
                base_args = {**sanitized_args}
                args_for_call = {**base_args}
                if auth_params:
                    args_for_call.update(auth_params)

                if (
                    self._security_engine
                    and tool_name not in self._auth_probe_done
                ):
                    findings = await self._run_negative_auth_probes(
                        tool_name, base_args, auth_params or {}
                    )
                    if findings:
                        self._auth_probe_findings[tool_name] = findings

                # High-level run progress at DEBUG to avoid noise
                self._logger.debug("Fuzzing %s (run %d/%d)", tool_name, i + 1, runs)

                # Call the tool with the generated arguments
                outcome: SecurityCallOutcome | None = None
                try:
                    outcome = await self._call_tool_with_security(
                        tool_name, args_for_call
                    )
                    if outcome.exception:
                        raise outcome.exception
                    result = outcome.result
                    spec_checks = spec_guard.check_tool_result_content(result)
                    spec_payload = (
                        {"spec_checks": spec_checks, "spec_scope": "tool_result"}
                        if spec_checks
                        else {}
                    )
                    response_signature = _response_shape_signature(result)
                    self.tool_mutator.record_feedback(
                        tool_name,
                        sanitized_args,
                        spec_checks=spec_checks,
                        response_signature=response_signature,
                    )
                    results.append(
                        {
                            "args": sanitized_args,
                            "result": result,
                            "safety_blocked": False,
                            "safety_sanitized": safety_sanitized,
                            "success": True,
                            "oracle_findings": outcome.oracle_findings,
                            "side_effects": outcome.side_effects,
                            "policy_violations": outcome.policy_violations,
                            "semantic_mismatch": outcome.semantic_mismatch,
                            **spec_payload,
                        }
                    )
                except Exception as e:
                    self._logger.warning("Exception calling tool %s: %s", tool_name, e)
                    self.tool_mutator.record_feedback(
                        tool_name, sanitized_args, exception=str(e)
                    )
                    results.append(
                        {
                            "args": sanitized_args,
                            "exception": str(e),
                            "safety_blocked": False,
                            "safety_sanitized": safety_sanitized,
                            "success": False,
                            "oracle_findings": outcome.oracle_findings
                            if outcome
                            else [],
                            "side_effects": outcome.side_effects if outcome else [],
                            "policy_violations": outcome.policy_violations
                            if outcome
                            else [],
                            "semantic_mismatch": outcome.semantic_mismatch
                            if outcome
                            else None,
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

    def _resolve_server_pid(self) -> int | None:
        proc = getattr(self.transport, "process", None)
        if proc is not None and hasattr(proc, "pid"):
            return proc.pid
        return None

    async def _run_stateful_sequences(self, tools: list[dict[str, Any]]) -> None:
        if not tools or not self._security_engine:
            return
        mutator = SequenceMutator(tools, self._sequence_context)
        sequences = mutator.build_sequences()
        if not sequences:
            return
        for sequence in sequences:
            try:
                context, results = await self._sequence_executor.execute_sequence(
                    sequence, self._sequence_context
                )
                self._sequence_context = context
                self._sequence_runs.append({"name": sequence.name, "results": results})
            except Exception as exc:
                self._logger.warning(
                    "Stateful sequence %s failed: %s", sequence.name, exc
                )

    async def _call_tool_with_security(
        self,
        tool_name: str,
        args_for_call: dict[str, Any],
    ) -> SecurityCallOutcome:
        if not self._security_engine:
            result = await self._rpc.call_tool(tool_name, args_for_call)
            return SecurityCallOutcome(
                result=result,
                exception=None,
                oracle_findings=[],
                side_effects=[],
                policy_violations=[],
                semantic_mismatch=None,
            )

        server_pid = self._resolve_server_pid()
        expectations = self._security_engine.pre_call_expectations(
            tool_name, args_for_call
        )
        snapshots: list[tuple[object, object | None]] = []
        for oracle in self._security_oracles:
            try:
                if isinstance(oracle, FilesystemSideEffectOracle):
                    snapshots.append((oracle, oracle.pre_call()))
                else:
                    snapshots.append((oracle, oracle.pre_call(server_pid)))
            except Exception as exc:
                self._logger.debug("Security oracle pre_call failed: %s", exc)
                snapshots.append((oracle, None))

        result: Any = None
        call_exception: Exception | None = None
        try:
            result = await self._rpc.call_tool(tool_name, args_for_call)
        except Exception as exc:
            call_exception = exc
        finally:
            oracle_findings: list[dict[str, Any]] = []
            side_effects: list[dict[str, Any]] = []
            for oracle, snapshot in snapshots:
                try:
                    if isinstance(oracle, FilesystemSideEffectOracle):
                        findings, effects = oracle.post_call(snapshot)
                    else:
                        findings, effects = oracle.post_call(server_pid, snapshot)
                except Exception as exc:
                    self._logger.debug("Security oracle post_call failed: %s", exc)
                    continue
                oracle_findings.extend(findings)
                side_effects.extend(effects)

            auth_findings = self._auth_probe_findings.pop(tool_name, [])
            if auth_findings:
                oracle_findings.extend(auth_findings)
            session_findings: list[dict[str, Any]] = []
            try:
                session_findings = await self._attempt_session_replay(tool_name)
            except Exception as exc:
                self._logger.debug("Session replay check failed: %s", exc)
            if session_findings:
                oracle_findings.extend(session_findings)

            verdict = self._security_engine.post_call_verdicts(
                success=call_exception is None,
                exception=call_exception,
                oracle_findings=oracle_findings,
                expectations=expectations,
            )

            return SecurityCallOutcome(
                result=result if call_exception is None else None,
                exception=call_exception,
                oracle_findings=oracle_findings,
                side_effects=side_effects,
                policy_violations=verdict.policy_violations,
                semantic_mismatch=verdict.semantic_mismatch,
            )

    def _unwrap_transport(self) -> Any:
        transport = self.transport
        while hasattr(transport, "_transport"):
            transport = getattr(transport, "_transport")
        return transport

    @contextmanager
    def _temporary_transport_attr(self, attr: str, value: Any):
        driver = self._unwrap_transport()
        previous = getattr(driver, attr, None)
        setattr(driver, attr, value)
        try:
            yield
        finally:
            setattr(driver, attr, previous)

    async def _run_negative_auth_probes(
        self,
        tool_name: str,
        base_args: dict[str, Any],
        auth_params: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if tool_name in self._auth_probe_done:
            return []
        self._auth_probe_done.add(tool_name)
        if not self.auth_manager:
            return []

        headers = self.auth_manager.get_auth_headers_for_tool(tool_name)
        params = auth_params if isinstance(auth_params, dict) else {}
        has_headers = bool(headers)
        has_params = bool(params)
        if not has_headers and not has_params:
            return []

        findings: list[dict[str, Any]] = []
        probe_args = dict(base_args)

        async def _call_probe(kwargs: dict[str, Any], header_override=None):
            try:
                if header_override is not None:
                    with self._temporary_transport_attr(
                        "auth_headers", header_override
                    ):
                        await self._rpc.call_tool(tool_name, kwargs)
                else:
                    await self._rpc.call_tool(tool_name, kwargs)
                return True
            except Exception:
                return False

        missing_success = await _call_probe(probe_args, {} if has_headers else None)
        if missing_success:
            findings.append(
                {
                    "oracle": "authz",
                    "type": "missing_auth",
                    "tool": tool_name,
                    "details": {
                        "args": probe_args,
                        "headers_removed": has_headers,
                        "params_removed": has_params,
                    },
                }
            )

        if has_headers or has_params:
            invalid_headers = self._mutate_headers(headers) if has_headers else {}
            invalid_params = self._mutate_params(params) if has_params else {}
            invalid_args = {**dict(base_args), **invalid_params}
            invalid_success = await _call_probe(
                invalid_args, invalid_headers if has_headers else None
            )
            if invalid_success:
                findings.append(
                    {
                        "oracle": "authz",
                        "type": "invalid_auth",
                        "tool": tool_name,
                        "details": {
                            "args": invalid_args,
                            "headers": invalid_headers if has_headers else None,
                            "params": invalid_params,
                        },
                    }
                )

        return findings

    def _mutate_headers(self, headers: dict[str, str] | None) -> dict[str, str]:
        if not headers:
            return {}
        mutated: dict[str, str] = {}
        for key, value in headers.items():
            mutated[key] = (
                f"{value}-invalid" if isinstance(value, str) else str(value)
            )
        return mutated

    def _mutate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        mutated: dict[str, Any] = {}
        for key, value in params.items():
            mutated[key] = self._mutate_value(value)
        return mutated

    def _mutate_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return f"{value}-invalid"
        if isinstance(value, bool):
            return not value
        if isinstance(value, (int, float)):
            return value + 1
        return "invalid"

    async def _attempt_session_replay(
        self, tool_name: str
    ) -> list[dict[str, Any]]:
        transport = self._unwrap_transport()
        if not hasattr(transport, "session_id"):
            return []
        previous_session_id = self._last_session_id
        current_session_id = getattr(transport, "session_id", None)
        if (
            not previous_session_id
            or not current_session_id
            or previous_session_id == current_session_id
        ):
            self._last_session_id = current_session_id
            return []
        if previous_session_id in self._session_replay_checked:
            self._last_session_id = current_session_id
            return []

        self._session_replay_checked.add(previous_session_id)
        success = False
        with self._temporary_transport_attr("session_id", previous_session_id):
            try:
                await self._rpc.get_tools()
                success = True
            except Exception:
                success = False

        self._last_session_id = getattr(transport, "session_id", current_session_id)
        if success:
            return [
                {
                    "oracle": "authz",
                    "type": "session_replay",
                    "tool": tool_name,
                    "previous_session_id": previous_session_id,
                }
            ]
        return []

    async def fuzz_all_tools(
        self,
        runs_per_tool: int = DEFAULT_TOOL_RUNS,
        tool_timeout: float | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Fuzz all tools from the server."""
        tools = await self._get_tools_from_server()
        await self._run_stateful_sequences(tools)
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
            tool_entry: dict[str, Any] = {"runs": results}
            if tool_name in self._tool_schema_checks:
                schema_checks = self._tool_schema_checks[tool_name]
                tool_entry["spec_checks"] = schema_checks
                tool_entry["spec_scope"] = "tool_schema"
                tool_entry["spec_checks_passed"] = not any(
                    str(check.get("status", "")).upper() == "FAIL"
                    for check in schema_checks
                )
            all_results[tool_name] = tool_entry

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
                        "label": f"tool:{tool_name}",
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
            outcome: SecurityCallOutcome | None = None
            try:
                outcome = await self._call_tool_with_security(tool_name, args_for_call)
                if outcome.exception:
                    raise outcome.exception
                result = outcome.result
                spec_checks = spec_guard.check_tool_result_content(result)
                spec_payload = (
                    {"spec_checks": spec_checks, "spec_scope": "tool_result"}
                    if spec_checks
                    else {}
                )
                response_signature = _response_shape_signature(result)
                self.tool_mutator.record_feedback(
                    tool_name,
                    sanitized_args,
                    spec_checks=spec_checks,
                    response_signature=response_signature,
                )
                processed.append(
                    {
                        "args": sanitized_args,
                        "label": f"tool:{tool_name}",
                        "result": result,
                        "safety_blocked": False,
                        "safety_sanitized": safety_sanitized,
                        "success": True,
                        "oracle_findings": outcome.oracle_findings,
                        "side_effects": outcome.side_effects,
                        "policy_violations": outcome.policy_violations,
                        "semantic_mismatch": outcome.semantic_mismatch,
                        **spec_payload,
                    }
                )
            except Exception as e:
                self.tool_mutator.record_feedback(
                    tool_name, sanitized_args, exception=str(e)
                )
                processed.append(
                    {
                        "args": sanitized_args,
                        "label": f"tool:{tool_name}",
                        "exception": str(e),
                        "safety_blocked": False,
                        "safety_sanitized": safety_sanitized,
                        "success": False,
                        "oracle_findings": outcome.oracle_findings
                        if outcome
                        else [],
                        "side_effects": outcome.side_effects if outcome else [],
                        "policy_violations": outcome.policy_violations
                        if outcome
                        else [],
                        "semantic_mismatch": outcome.semantic_mismatch
                        if outcome
                        else None,
                    }
                )

        return processed

    async def fuzz_tool_both_phases(
        self, tool: dict[str, Any], runs_per_phase: int = 5
    ) -> dict[str, Any]:
        """Fuzz a specific tool in both realistic and aggressive phases."""
        tool_name = tool.get("name", "unknown")
        self._logger.info(f"Starting two-phase fuzzing for tool: {tool_name}")

        try:
            # Phase 1: Realistic fuzzing
            self._logger.info(f"Phase 1 (Realistic): {tool_name}")
            realistic_results = []
            for i in range(runs_per_phase):
                args = await self.tool_mutator.mutate(tool, phase="realistic")
                realistic_results.append({"args": args})
            realistic_processed = await self._process_fuzz_results(
                tool_name, realistic_results
            )

            # Phase 2: Aggressive fuzzing
            self._logger.info(f"Phase 2 (Aggressive): {tool_name}")
            aggressive_results = []
            for i in range(runs_per_phase):
                args = await self.tool_mutator.mutate(tool)
                aggressive_results.append({"args": args})
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
                if tool_name in self._tool_schema_checks:
                    schema_checks = self._tool_schema_checks[tool_name]
                    phase_results["spec_checks"] = schema_checks
                    phase_results["spec_scope"] = "tool_schema"
                    phase_results["spec_checks_passed"] = not any(
                        str(check.get("status", "")).upper() == "FAIL"
                        for check in schema_checks
                    )
                all_results[tool_name] = phase_results

            return all_results

        except Exception as e:
            self._logger.error(f"Failed to fuzz all tools (two-phase): {e}")
            return {}

    async def shutdown(self):
        """Shutdown the tool client."""
        # No cleanup needed for mutator
        pass

    @property
    def sequence_logs(self) -> list[dict[str, Any]]:
        """Return stateful sequence runs for diagnostics."""
        return list(self._sequence_runs)


def _response_shape_signature(response: Any) -> str | None:
    if response is None:
        return None
    if isinstance(response, dict):
        keys = ",".join(sorted(response.keys()))
        content = response.get("content")
        if isinstance(content, list):
            types = sorted(
                {
                    item.get("type")
                    for item in content
                    if isinstance(item, dict) and isinstance(item.get("type"), str)
                }
            )
            type_sig = ",".join(types) if types else "unknown"
            return f"dict:{keys}:content[{type_sig}]"
        return f"dict:{keys}"
    if isinstance(response, list):
        return f"list:{len(response)}"
    return f"type:{type(response).__name__}"
