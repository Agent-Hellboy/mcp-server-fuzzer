#!/usr/bin/env python3
"""
Protocol Client Module

This module provides functionality for fuzzing MCP protocol types.
"""

import asyncio
import json
import logging
import random
import traceback
from pathlib import Path
from typing import Any

from .. import spec_guard
from ..exceptions import ServerCrashError
from ..fuzz_engine.mutators import ProtocolMutator
from ..fuzz_engine.mutators.seed_mutation import mutate_seed_payload
from ..fuzz_engine.mutators.seed_pool import SeedPool
from .outcomes import FuzzOutcome, classify_protocol_run
from ..protocol_registry import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST
from ..safety_system.safety import CombinedSafetyProvider, ProtocolSafetyProvider
from ..types import PREVIEW_LENGTH, ProtocolFuzzResult, SafetyCheckResult
from .protocol_listings import ProtocolListingsMixin
from .protocol_send_handlers import ProtocolSendHandlers
from .protocol_specs import SUPPORTED_PROTOCOL_TYPES, _response_shape_signature

__all__ = ["ProtocolClient", "SUPPORTED_PROTOCOL_TYPES"]


class ProtocolClient(ProtocolListingsMixin, ProtocolSendHandlers):
    """Client for fuzzing MCP protocol types."""

    def __init__(
        self,
        transport,
        safety_system: CombinedSafetyProvider | None = None,
        max_concurrency: int = 5,
        corpus_root: Path | None = None,
        havoc_mode: bool = False,
        seed_pool: SeedPool | None = None,
    ):
        """
        Initialize the protocol client.

        Args:
            transport: Transport protocol for server communication
            safety_system: Safety system for filtering operations
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self.safety_system = safety_system
        if self.safety_system is not None and not isinstance(
            self.safety_system, ProtocolSafetyProvider
        ):
            raise TypeError(
                "safety_system must implement protocol safety hooks "
                "(should_block_protocol_message, sanitize_protocol_message, "
                "get_blocking_reason)"
            )
        # Important: let ProtocolClient own sending (safety checks happen here)
        self.protocol_mutator = ProtocolMutator(
            corpus_dir=corpus_root,
            havoc_mode=havoc_mode,
            seed_pool=seed_pool,
        )
        self.max_concurrency = max(1, max_concurrency)
        self._logger = logging.getLogger(__name__)
        self._observed_resources: set[str] = set()
        self._observed_prompts: set[str] = set()
        self._observed_tools: dict[str, dict[str, Any]] = {}
        self._observed_tasks: dict[str, dict[str, Any]] = {}
        self._successful_requests: dict[str, list[dict[str, Any]]] = {}
        self._max_successful_requests = 25

    async def _check_safety_for_protocol_message(
        self, protocol_type: str, fuzz_data: dict[str, Any]
    ) -> SafetyCheckResult:
        """Check if a protocol message should be blocked by the safety system.

        Args:
            protocol_type: Type of protocol message
            fuzz_data: Message data to check

        Returns:
            Dictionary with safety check results containing:
            - blocked: True if message should be blocked
            - sanitized: True if message was sanitized
            - blocking_reason: Reason for blocking (if blocked)
            - data: Original or sanitized data
        """
        safety_sanitized = False
        blocking_reason = None
        modified_data = fuzz_data

        if not self.safety_system:
            return {
                "blocked": False,
                "sanitized": False,
                "blocking_reason": None,
                "data": fuzz_data,
            }

        if self.safety_system.should_block_protocol_message(protocol_type, fuzz_data):
            blocking_reason = (
                self.safety_system.get_blocking_reason() or "blocked_by_safety_system"
            )
            self._logger.warning(
                f"Safety system blocked {protocol_type} message: {blocking_reason}"
            )
            return {
                "blocked": True,
                "sanitized": False,
                "blocking_reason": blocking_reason,
                "data": fuzz_data,
            }

        # Sanitize message
        original_data = fuzz_data.copy() if isinstance(fuzz_data, dict) else fuzz_data
        modified_data = self.safety_system.sanitize_protocol_message(
            protocol_type, fuzz_data
        )
        safety_sanitized = modified_data != original_data

        return {
            "blocked": False,
            "sanitized": safety_sanitized,
            "blocking_reason": None,
            "data": modified_data,
        }

    async def _execute_protocol_fuzz(
        self,
        protocol_type: str,
        fuzz_data: dict[str, Any],
        label: str,
    ) -> ProtocolFuzzResult:
        try:
            preview = json.dumps(fuzz_data, indent=2)[:PREVIEW_LENGTH]
        except Exception:
            preview_text = str(fuzz_data) if fuzz_data is not None else "null"
            preview = preview_text[:PREVIEW_LENGTH]
        self._logger.info(
            "Fuzzed %s (%s) with data: %s...",
            protocol_type,
            label,
            preview,
        )

        safety_result = await self._check_safety_for_protocol_message(
            protocol_type, fuzz_data
        )
        if safety_result["blocked"]:
            self._logger.warning(
                "Blocked %s by safety system: %s",
                protocol_type,
                safety_result.get("blocking_reason"),
            )
            return {
                "fuzz_data": fuzz_data,
                "label": label,
                "result": {"response": None, "error": "blocked_by_safety_system"},
                "safety_blocked": True,
                "safety_sanitized": False,
                "success": False,
            }

        data_to_send = safety_result["data"]
        send_exception: Exception | None = None
        try:
            server_response = await self._send_protocol_request(
                protocol_type, data_to_send
            )
            server_error = None
        except Exception as send_exc:
            send_exception = send_exc
            server_response = None
            server_error = str(send_exc)

        result = {"response": server_response, "error": server_error}
        safety_blocked = safety_result["blocked"]
        safety_sanitized = safety_result["sanitized"]
        success, outcome = classify_protocol_run(
            server_response=server_response,
            server_error=server_error,
            exception=send_exception,
            safety_blocked=safety_blocked,
        )
        spec_checks: list[dict[str, Any]] = []
        spec_scope: str | None = None
        if isinstance(server_response, dict):
            payload = server_response.get("result", server_response)
            method = (
                data_to_send.get("method") if isinstance(data_to_send, dict) else None
            )
            spec_checks, spec_scope = spec_guard.get_spec_checks_for_protocol_type(
                protocol_type, payload, method=method
            )

        if (
            server_error is None
            and isinstance(server_response, dict)
            and "error" not in server_response
        ):
            self._record_successful_request(
                protocol_type, data_to_send, server_response
            )

        error_signature = server_error
        if (
            error_signature is None
            and isinstance(server_response, dict)
            and "error" in server_response
        ):
            err = server_response.get("error")
            if isinstance(err, dict):
                code = err.get("code")
                message = err.get("message")
                error_signature = f"jsonrpc:{code}:{message}"
            else:
                error_signature = f"jsonrpc:{err}"

        response_signature = _response_shape_signature(server_response)
        self.protocol_mutator.record_feedback(
            protocol_type,
            data_to_send,
            server_error=error_signature,
            spec_checks=spec_checks,
            response_signature=response_signature,
        )

        run_result = {
            "fuzz_data": fuzz_data,
            "label": label,
            "result": result,
            "safety_blocked": safety_blocked,
            "safety_sanitized": safety_sanitized,
            "spec_checks": spec_checks,
            "spec_scope": spec_scope,
            "success": success,
            "outcome": str(outcome),
            "accepted_malformed": outcome == FuzzOutcome.ACCEPTED_MALFORMED,
            "server_rejected_input": outcome == FuzzOutcome.SERVER_REJECTED,
        }
        if outcome == FuzzOutcome.CRASHED and isinstance(
            send_exception, ServerCrashError
        ):
            run_result["crash"] = dict(getattr(send_exception, "context", None) or {})
            self._logger.error(
                "Server CRASHED while fuzzing %s: %s",
                protocol_type,
                run_result["crash"],
            )
        return run_result

    async def fuzz_stateful_sequences(
        self, runs: int = 5, phase: str = "realistic"
    ) -> list[ProtocolFuzzResult]:
        """Fuzz using learned stateful sequences."""
        results: list[ProtocolFuzzResult] = []
        if runs <= 0:
            return results

        for run_index in range(runs):
            sequence = await self._build_stateful_sequence(phase)
            for step_index, (protocol_type, fuzz_data) in enumerate(sequence):
                label = f"sequence {run_index + 1}/{runs} step {step_index + 1}"
                results.append(
                    await self._execute_protocol_fuzz(protocol_type, fuzz_data, label)
                )
        return results

    async def _build_stateful_sequence(
        self, phase: str
    ) -> list[tuple[str, dict[str, Any]]]:
        sequence: list[tuple[str, dict[str, Any]]] = []
        for protocol_type in (
            "InitializeRequest",
            "InitializedNotification",
            "ListToolsRequest",
            "ListResourcesRequest",
            "ListPromptsRequest",
        ):
            sequence.append(
                (protocol_type, await self._pick_learned_request(protocol_type, phase))
            )

        if self._observed_resources:
            read_req = await self._pick_learned_request(READ_RESOURCE_REQUEST, phase)
            params = self._extract_params(read_req)
            params["uri"] = random.choice(sorted(self._observed_resources))
            read_req["params"] = params
            sequence.append((READ_RESOURCE_REQUEST, read_req))

        if self._observed_prompts:
            prompt_req = await self._pick_learned_request(GET_PROMPT_REQUEST, phase)
            params = self._extract_params(prompt_req)
            params["name"] = random.choice(sorted(self._observed_prompts))
            if "arguments" not in params:
                params["arguments"] = {}
            prompt_req["params"] = params
            sequence.append((GET_PROMPT_REQUEST, prompt_req))

        direct_tool = self._choose_observed_tool(allow_task_required=False)
        if direct_tool is not None:
            tool_req = await self._pick_learned_request("CallToolRequest", phase)
            params = self._extract_params(tool_req)
            params["name"] = direct_tool["name"]
            params["arguments"] = self._build_tool_arguments(direct_tool)
            params.pop("task", None)
            tool_req["params"] = params
            sequence.append(("CallToolRequest", tool_req))

        task_tool = self._choose_observed_tool(require_task_support=True)
        if task_tool is not None:
            task_tool_req = await self._pick_learned_request("CallToolRequest", phase)
            params = self._extract_params(task_tool_req)
            params["name"] = task_tool["name"]
            params["arguments"] = self._build_tool_arguments(task_tool)
            params["task"] = {"ttl": 60000}
            task_tool_req["params"] = params
            sequence.append(("CallToolRequest", task_tool_req))
            sequence.append(
                (
                    "ListTasksRequest",
                    await self._pick_learned_request("ListTasksRequest", phase),
                )
            )

        if self._observed_tasks:
            sequence.append(
                (
                    "ListTasksRequest",
                    await self._pick_learned_request("ListTasksRequest", phase),
                )
            )

            task = self._choose_observed_task()
            if task is not None:
                task_id = task["taskId"]
                for protocol_type in (
                    "GetTaskRequest",
                    "GetTaskPayloadRequest",
                    "CancelTaskRequest",
                ):
                    task_req = await self._pick_learned_request(protocol_type, phase)
                    params = self._extract_params(task_req)
                    params["taskId"] = task_id
                    task_req["params"] = params
                    sequence.append((protocol_type, task_req))

        sequence.append(
            ("PingRequest", await self._pick_learned_request("PingRequest", phase))
        )
        return sequence

    async def _pick_learned_request(
        self, protocol_type: str, phase: str
    ) -> dict[str, Any]:
        learned = self._successful_requests.get(protocol_type, [])
        if learned:
            base = random.choice(learned)
            mutated = mutate_seed_payload(base, stack=1)
            if "jsonrpc" in base:
                mutated["jsonrpc"] = base.get("jsonrpc", "2.0")
            if "method" in base and "method" not in mutated:
                mutated["method"] = base["method"]
            return mutated
        try:
            return await self.protocol_mutator.mutate(protocol_type, phase=phase)
        except Exception:
            return {"jsonrpc": "2.0", "method": "unknown", "params": {}}

    async def _process_single_protocol_fuzz(
        self,
        protocol_type: str,
        run_index: int,
        total_runs: int,
        phase: str = "realistic",
    ) -> ProtocolFuzzResult:
        """Process a single protocol fuzzing run.

        Args:
            protocol_type: Type of protocol to fuzz
            run_index: Current run index (0-based)
            total_runs: Total number of runs

        Returns:
            Dictionary with fuzzing results
        """
        label = f"run {run_index + 1}/{total_runs}"
        try:
            # Generate fuzz data using mutator (no send); client handles safety + send
            fuzz_data = await self.protocol_mutator.mutate(protocol_type, phase=phase)

            if fuzz_data is None:
                raise ValueError(f"No fuzz_data returned for {protocol_type}")

            return await self._execute_protocol_fuzz(protocol_type, fuzz_data, label)

        except Exception as e:
            self._logger.warning(f"Exception during fuzzing {protocol_type}: {e}")
            return {
                "fuzz_data": (fuzz_data if "fuzz_data" in locals() else None),
                "label": label,
                "exception": str(e),
                "traceback": traceback.format_exc(),
                "success": False,
                "safety_blocked": False,
                "safety_sanitized": False,
            }

    async def _run_bounded(self, count: int, factory) -> list[ProtocolFuzzResult]:
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _limited(index: int):
            async with semaphore:
                return await factory(index)

        return list(await asyncio.gather(*(_limited(i) for i in range(count))))

    async def fuzz_protocol_type(
        self, protocol_type: str, runs: int = 10, phase: str = "realistic"
    ) -> list[ProtocolFuzzResult]:
        """Fuzz a specific protocol type."""
        results = await self._run_bounded(
            runs,
            lambda i: self._process_single_protocol_fuzz(
                protocol_type, i, runs, phase
            ),
        )
        await self._append_follow_up_results(results, protocol_type)
        return results

    def _get_protocol_types(self) -> list[str]:
        """Get list of protocol types to fuzz.

        Returns:
            List of protocol type strings
        """
        return list(SUPPORTED_PROTOCOL_TYPES)

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5, phase: str = "realistic"
    ) -> dict[str, list[ProtocolFuzzResult]]:
        """Fuzz all protocol types using ProtocolClient safety + sending."""
        try:
            protocol_types = self._get_protocol_types()
            if not protocol_types:
                self._logger.warning("No protocol types available")
                return {}
            all_results: dict[str, list[dict[str, Any]]] = {}
            for pt in protocol_types:
                per_type = await self._run_bounded(
                    runs_per_type,
                    lambda i, protocol=pt: self._process_single_protocol_fuzz(
                        protocol, i, runs_per_type, phase
                    ),
                )
                all_results[pt] = per_type
            for protocol_type, results in all_results.items():
                await self._append_follow_up_results(results, protocol_type)
            return all_results
        except Exception as e:
            self._logger.error(f"Failed to fuzz all protocol types: {e}")
            return {}

    async def _append_follow_up_results(
        self,
        results: list[ProtocolFuzzResult],
        protocol_type: str,
    ) -> None:
        if protocol_type == READ_RESOURCE_REQUEST:
            results.extend(await self._fuzz_listed_resources())
            return
        if protocol_type == GET_PROMPT_REQUEST:
            results.extend(await self._fuzz_listed_prompts())
            return
        if protocol_type == "CallToolRequest":
            results.extend(await self._fuzz_listed_tools())
            return
        if protocol_type in {
            "ListTasksRequest",
            "GetTaskRequest",
            "GetTaskPayloadRequest",
            "CancelTaskRequest",
        }:
            results.extend(await self._fuzz_observed_tasks(protocol_type))

    async def shutdown(self) -> None:
        """Shutdown the protocol client."""
        return None
