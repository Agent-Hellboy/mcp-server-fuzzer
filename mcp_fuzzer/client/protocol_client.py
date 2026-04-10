#!/usr/bin/env python3
"""
Protocol Client Module

This module provides functionality for fuzzing MCP protocol types.
"""

import copy
import json
import logging
import random
import traceback
from pathlib import Path
from typing import Any

from ..types import ProtocolFuzzResult, SafetyCheckResult, PREVIEW_LENGTH
from ..protocol_types import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST
from ..protocol_registry import DEFAULT_PROTOCOL_TYPES
from ..utils.schema_helpers import _build_tool_arguments, _tool_task_support

from ..fuzz_engine.mutators import ProtocolMutator
from ..fuzz_engine.mutators.seed_mutation import mutate_seed_payload
from .. import spec_guard
from ..fuzz_engine.executor import ProtocolExecutor
from ..safety_system.safety import CombinedSafetyProvider

# Centralized allow-list for protocol types that can be fuzzed
# This should stay in sync with ProtocolExecutor.PROTOCOL_TYPES
ALLOWED_PROTOCOL_TYPES = frozenset(DEFAULT_PROTOCOL_TYPES + (
    "InitializedNotification",
    "ProgressNotification",
    READ_RESOURCE_REQUEST,
    "ListResourceTemplatesRequest",
    "CompleteRequest",
    "ElicitRequest",
    "SubscribeRequest",
    "UnsubscribeRequest",
    "GenericJSONRPCRequest",
))


class ProtocolClient:
    """Client for fuzzing MCP protocol types."""

    def __init__(
        self,
        transport,
        safety_system: CombinedSafetyProvider | None = None,
        max_concurrency: int = 5,
        corpus_root: Path | None = None,
        havoc_mode: bool = False,
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
        # Important: let ProtocolClient own sending (safety checks happen here)
        self.protocol_mutator = ProtocolMutator(
            corpus_dir=corpus_root, havoc_mode=havoc_mode
        )
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
        try:
            server_response = await self._send_protocol_request(
                protocol_type, data_to_send
            )
            server_error = None
            success = True
        except Exception as send_exc:
            server_response = None
            server_error = str(send_exc)
            success = False

        result = {"response": server_response, "error": server_error}
        safety_blocked = safety_result["blocked"]
        safety_sanitized = safety_result["sanitized"]
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

        return {
            "fuzz_data": fuzz_data,
            "label": label,
            "result": result,
            "safety_blocked": safety_blocked,
            "safety_sanitized": safety_sanitized,
            "spec_checks": spec_checks,
            "spec_scope": spec_scope,
            "success": success,
        }

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

    def _record_successful_request(
        self,
        protocol_type: str,
        fuzz_data: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        if isinstance(fuzz_data, dict):
            pool = self._successful_requests.setdefault(protocol_type, [])
            pool.append(copy.deepcopy(fuzz_data))
            if len(pool) > self._max_successful_requests:
                del pool[0 : len(pool) - self._max_successful_requests]

        for resource in self._extract_list_items(response, "resources"):
            if isinstance(resource, dict):
                uri = resource.get("uri")
                if isinstance(uri, str):
                    self._observed_resources.add(uri)

        for prompt in self._extract_list_items(response, "prompts"):
            if isinstance(prompt, dict):
                name = prompt.get("name")
                if isinstance(name, str):
                    self._observed_prompts.add(name)

        for tool in self._extract_list_items(response, "tools"):
            self._remember_tool(tool)

        for task in self._extract_list_items(response, "tasks"):
            self._remember_task(task)

        for payload in self._extract_payload_dicts(response):
            task = payload.get("task")
            if isinstance(task, dict):
                self._remember_task(task)
                continue
            if self._looks_like_task(payload):
                self._remember_task(payload)

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
            }

    async def fuzz_protocol_type(
        self, protocol_type: str, runs: int = 10, phase: str = "realistic"
    ) -> list[ProtocolFuzzResult]:
        """Fuzz a specific protocol type."""
        results = []

        for i in range(runs):
            result = await self._process_single_protocol_fuzz(
                protocol_type, i, runs, phase
            )
            results.append(result)

        if protocol_type == READ_RESOURCE_REQUEST:
            results.extend(await self._fuzz_listed_resources())
        elif protocol_type == GET_PROMPT_REQUEST:
            results.extend(await self._fuzz_listed_prompts())
        elif protocol_type == "CallToolRequest":
            results.extend(await self._fuzz_listed_tools())
        elif protocol_type in {
            "ListTasksRequest",
            "GetTaskRequest",
            "GetTaskPayloadRequest",
            "CancelTaskRequest",
        }:
            results.extend(await self._fuzz_observed_tasks(protocol_type))

        return results

    async def _get_protocol_types(self) -> list[str]:
        """Get list of protocol types to fuzz.

        Returns:
            List of protocol type strings
        """
        try:
            # Use the class-level protocol type list from ProtocolExecutor
            # Filter to only request/notification types (exclude result types)
            return [
                pt
                for pt in getattr(ProtocolExecutor, "PROTOCOL_TYPES", ())
                if pt in ALLOWED_PROTOCOL_TYPES
            ]
        except Exception as e:
            self._logger.error(f"Failed to get protocol types: {e}")
            return []

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5, phase: str = "realistic"
    ) -> dict[str, list[ProtocolFuzzResult]]:
        """Fuzz all protocol types using ProtocolClient safety + sending."""
        try:
            protocol_types = await self._get_protocol_types()
            if not protocol_types:
                self._logger.warning("No protocol types available")
                return {}
            all_results: dict[str, list[dict[str, Any]]] = {}
            for pt in protocol_types:
                per_type: list[dict[str, Any]] = []
                for i in range(runs_per_type):
                    per_type.append(
                        await self._process_single_protocol_fuzz(
                            pt, i, runs_per_type, phase
                        )
                    )
                all_results[pt] = per_type
            if READ_RESOURCE_REQUEST in all_results:
                all_results[READ_RESOURCE_REQUEST].extend(
                    await self._fuzz_listed_resources()
                )
            if GET_PROMPT_REQUEST in all_results:
                all_results[GET_PROMPT_REQUEST].extend(
                    await self._fuzz_listed_prompts()
                )
            if "CallToolRequest" in all_results:
                all_results["CallToolRequest"].extend(await self._fuzz_listed_tools())
            for protocol_type in (
                "ListTasksRequest",
                "GetTaskRequest",
                "GetTaskPayloadRequest",
                "CancelTaskRequest",
            ):
                if protocol_type in all_results:
                    all_results[protocol_type].extend(
                        await self._fuzz_observed_tasks(protocol_type)
                    )
            return all_results
        except Exception as e:
            self._logger.error(f"Failed to fuzz all protocol types: {e}")
            return {}

    def _extract_params(self, data: Any) -> dict[str, Any]:
        """Extract parameters from data, safely handling non-dict inputs.

        Args:
            data: Input data that may or may not be a dict

        Returns:
            Dictionary of parameters, or empty dict if not available
        """
        if isinstance(data, dict):
            params = data.get("params", {})
            if isinstance(params, dict):
                return params
        self._logger.debug(
            "Coercing non-dict params to empty dict for %s", type(data).__name__
        )
        return {}

    @staticmethod
    def _extract_list_items(result: Any, key: str) -> list[Any]:
        if not isinstance(result, dict):
            return []
        if isinstance(result.get(key), list):
            return result[key]
        inner = result.get("result")
        if isinstance(inner, dict) and isinstance(inner.get(key), list):
            return inner[key]
        return []

    @staticmethod
    def _extract_payload_dicts(result: Any) -> list[dict[str, Any]]:
        payloads: list[dict[str, Any]] = []
        if isinstance(result, dict):
            payloads.append(result)
            inner = result.get("result")
            if isinstance(inner, dict):
                payloads.append(inner)
        return payloads

    @staticmethod
    def _looks_like_task(value: Any) -> bool:
        return (
            isinstance(value, dict)
            and isinstance(value.get("taskId"), str)
            and isinstance(value.get("status"), str)
        )

    def _remember_tool(self, tool: Any) -> None:
        if not isinstance(tool, dict):
            return
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            return
        self._observed_tools[name] = copy.deepcopy(tool)

    def _remember_task(self, task: Any) -> None:
        if not self._looks_like_task(task):
            return
        task_id = task["taskId"]
        self._observed_tasks[task_id] = copy.deepcopy(task)

    def _choose_observed_tool(
        self,
        *,
        allow_task_required: bool = True,
        require_task_support: bool = False,
    ) -> dict[str, Any] | None:
        tools = list(self._observed_tools.values())
        random.shuffle(tools)
        for tool in tools:
            task_support = _tool_task_support(tool)
            if require_task_support and task_support not in {"optional", "required"}:
                continue
            if not allow_task_required and task_support == "required":
                continue
            return copy.deepcopy(tool)
        return None

    def _choose_observed_task(self) -> dict[str, Any] | None:
        if not self._observed_tasks:
            return None
        task_id = random.choice(sorted(self._observed_tasks))
        return copy.deepcopy(self._observed_tasks[task_id])

    def _build_tool_arguments(self, tool: dict[str, Any]) -> dict[str, Any]:
        return _build_tool_arguments(tool)

    async def _fetch_listed_resources(self) -> list[dict[str, Any]]:
        try:
            result = await self.transport.send_request("resources/list", {})
        except Exception as exc:
            self._logger.warning("Failed to list resources: %s", exc)
            return []
        items = self._extract_list_items(result, "resources")
        return [item for item in items if isinstance(item, dict)]

    async def _fetch_listed_prompts(self) -> list[dict[str, Any]]:
        try:
            result = await self.transport.send_request("prompts/list", {})
        except Exception as exc:
            self._logger.warning("Failed to list prompts: %s", exc)
            return []
        items = self._extract_list_items(result, "prompts")
        return [item for item in items if isinstance(item, dict)]

    async def _fetch_listed_tools(self) -> list[dict[str, Any]]:
        try:
            result = await self.transport.send_request("tools/list", {})
        except Exception as exc:
            self._logger.warning("Failed to list tools: %s", exc)
            return []
        items = [
            item
            for item in self._extract_list_items(result, "tools")
            if isinstance(item, dict)
        ]
        for tool in items:
            self._remember_tool(tool)
        return items

    async def _fetch_listed_tasks(self) -> list[dict[str, Any]]:
        try:
            result = await self.transport.send_request("tasks/list", {})
        except Exception as exc:
            self._logger.warning("Failed to list tasks: %s", exc)
            return []
        items = [
            item
            for item in self._extract_list_items(result, "tasks")
            if isinstance(item, dict)
        ]
        for task in items:
            self._remember_task(task)
        return items

    async def _process_protocol_request(
        self,
        protocol_type: str,
        method: str,
        params: dict[str, Any],
        label: str,
    ) -> ProtocolFuzzResult:
        fuzz_data = {"jsonrpc": "2.0", "method": method, "params": params}
        return await self._execute_protocol_fuzz(protocol_type, fuzz_data, label)

    async def _fuzz_listed_resources(self) -> list[ProtocolFuzzResult]:
        results: list[ProtocolFuzzResult] = []
        resources = await self._fetch_listed_resources()
        for resource in resources:
            uri = resource.get("uri")
            if not isinstance(uri, str) or not uri:
                continue
            results.append(
                await self._process_protocol_request(
                    READ_RESOURCE_REQUEST,
                    "resources/read",
                    {"uri": uri},
                    f"resource:{uri}",  # label format: "{prefix}:{name}"
                )
            )
        return results

    async def _fuzz_listed_prompts(self) -> list[ProtocolFuzzResult]:
        results: list[ProtocolFuzzResult] = []
        prompts = await self._fetch_listed_prompts()
        for prompt in prompts:
            name = prompt.get("name")
            if not isinstance(name, str) or not name:
                continue
            results.append(
                await self._process_protocol_request(
                    GET_PROMPT_REQUEST,
                    "prompts/get",
                    {"name": name, "arguments": {}},
                    f"prompt:{name}",  # label format: "{prefix}:{name}"
                )
            )
        return results

    async def _fuzz_listed_tools(self) -> list[ProtocolFuzzResult]:
        results: list[ProtocolFuzzResult] = []
        tools = await self._fetch_listed_tools()
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                continue

            arguments = self._build_tool_arguments(tool)
            task_support = self._tool_task_support(tool)
            if task_support != "required":
                results.append(
                    await self._process_protocol_request(
                        "CallToolRequest",
                        "tools/call",
                        {"name": name, "arguments": arguments},
                        f"tool:{name}",
                    )
                )

            if task_support in {"optional", "required"}:
                results.append(
                    await self._process_protocol_request(
                        "CallToolRequest",
                        "tools/call",
                        {
                            "name": name,
                            "arguments": arguments,
                            "task": {"ttl": 60000},
                        },
                        f"tool-task:{name}",
                    )
                )
        return results

    async def _fuzz_observed_tasks(
        self, protocol_type: str | None = None
    ) -> list[ProtocolFuzzResult]:
        results: list[ProtocolFuzzResult] = []
        tasks = await self._fetch_listed_tasks()
        if not tasks:
            tasks = [copy.deepcopy(task) for task in self._observed_tasks.values()]

        if protocol_type in {None, "ListTasksRequest"}:
            results.append(
                await self._process_protocol_request(
                    "ListTasksRequest",
                    "tasks/list",
                    {},
                    "tasks:list",
                )
            )
            if protocol_type == "ListTasksRequest":
                return results

        for task in tasks:
            task_id = task.get("taskId")
            if not isinstance(task_id, str) or not task_id:
                continue

            if protocol_type in {None, "GetTaskRequest"}:
                results.append(
                    await self._process_protocol_request(
                        "GetTaskRequest",
                        "tasks/get",
                        {"taskId": task_id},
                        f"task:{task_id}",
                    )
                )

            if protocol_type in {None, "GetTaskPayloadRequest"}:
                results.append(
                    await self._process_protocol_request(
                        "GetTaskPayloadRequest",
                        "tasks/result",
                        {"taskId": task_id},
                        f"task-result:{task_id}",
                    )
                )

            if protocol_type in {None, "CancelTaskRequest"}:
                results.append(
                    await self._process_protocol_request(
                        "CancelTaskRequest",
                        "tasks/cancel",
                        {"taskId": task_id},
                        f"task-cancel:{task_id}",
                    )
                )
        return results

    async def _send_protocol_request(
        self, protocol_type: str, data: dict[str, Any]
    ) -> dict[str, Any]:
        """Send a protocol request based on the type."""
        handler = {
            "InitializeRequest": self._send_initialize_request,
            "InitializedNotification": self._send_initialized_notification,
            "ProgressNotification": self._send_progress_notification,
            "CancelledNotification": self._send_cancelled_notification,
            "ListToolsRequest": self._send_list_tools_request,
            "CallToolRequest": self._send_call_tool_request,
            "ListResourcesRequest": self._send_list_resources_request,
            READ_RESOURCE_REQUEST: self._send_read_resource_request,
            "ListResourceTemplatesRequest": self._send_list_resource_templates_request,
            "SetLevelRequest": self._send_set_level_request,
            "CreateMessageRequest": self._send_create_message_request,
            "ListPromptsRequest": self._send_list_prompts_request,
            GET_PROMPT_REQUEST: self._send_get_prompt_request,
            "ListRootsRequest": self._send_list_roots_request,
            "SubscribeRequest": self._send_subscribe_request,
            "UnsubscribeRequest": self._send_unsubscribe_request,
            "CompleteRequest": self._send_complete_request,
            "ElicitRequest": self._send_elicit_request,
            "ListTasksRequest": self._send_list_tasks_request,
            "GetTaskRequest": self._send_get_task_request,
            "GetTaskPayloadRequest": self._send_get_task_payload_request,
            "CancelTaskRequest": self._send_cancel_task_request,
            "PingRequest": self._send_ping_request,
        }.get(protocol_type, self._send_generic_request)
        return await handler(data)

    async def _send_notification(self, method: str, data: Any) -> dict[str, str]:
        params = self._extract_params(data)
        await self.transport.send_notification(method, params)
        return {"status": "notification_sent"}

    async def _send_initialize_request(self, data: Any) -> dict[str, Any]:
        """Send an initialize request."""
        return await self._send_request("initialize", data)

    async def _send_initialized_notification(self, data: Any) -> dict[str, str]:
        """Send the initialized notification."""
        return await self._send_notification("notifications/initialized", data)

    async def _send_progress_notification(self, data: Any) -> dict[str, str]:
        """Send a progress notification as JSON-RPC notification (no id)."""
        return await self._send_notification("notifications/progress", data)

    async def _send_cancelled_notification(self, data: Any) -> dict[str, str]:
        """Send a cancelled notification as JSON-RPC notification (no id)."""
        return await self._send_notification("notifications/cancelled", data)

    async def _send_list_tools_request(self, data: Any) -> dict[str, Any]:
        """Send a list tools request."""
        return await self._send_request("tools/list", data)

    async def _send_call_tool_request(self, data: Any) -> dict[str, Any]:
        """Send a tool call request."""
        return await self._send_request("tools/call", data)

    async def _send_list_resources_request(self, data: Any) -> dict[str, Any]:
        """Send a list resources request."""
        return await self._send_request("resources/list", data)

    async def _send_read_resource_request(self, data: Any) -> dict[str, Any]:
        """Send a read resource request."""
        return await self._send_request("resources/read", data)

    async def _send_list_resource_templates_request(self, data: Any) -> dict[str, Any]:
        """Send a list resource templates request."""
        return await self._send_request("resources/templates/list", data)

    async def _send_set_level_request(self, data: Any) -> dict[str, Any]:
        """Send a set level request."""
        return await self._send_request("logging/setLevel", data)

    async def _send_create_message_request(self, data: Any) -> dict[str, Any]:
        """Send a create message request."""
        return await self._send_request("sampling/createMessage", data)

    async def _send_list_prompts_request(self, data: Any) -> dict[str, Any]:
        """Send a list prompts request."""
        return await self._send_request("prompts/list", data)

    async def _send_get_prompt_request(self, data: Any) -> dict[str, Any]:
        """Send a get prompt request."""
        return await self._send_request("prompts/get", data)

    async def _send_list_roots_request(self, data: Any) -> dict[str, Any]:
        """Send a list roots request."""
        return await self._send_request("roots/list", data)

    async def _send_subscribe_request(self, data: Any) -> dict[str, Any]:
        """Send a subscribe request."""
        return await self._send_request("resources/subscribe", data)

    async def _send_unsubscribe_request(self, data: Any) -> dict[str, Any]:
        """Send an unsubscribe request."""
        return await self._send_request("resources/unsubscribe", data)

    async def _send_complete_request(self, data: Any) -> dict[str, Any]:
        """Send a complete request."""
        return await self._send_request("completion/complete", data)

    async def _send_elicit_request(self, data: Any) -> dict[str, Any]:
        """Send an elicitation request."""
        return await self._send_request("elicitation/create", data)

    async def _send_list_tasks_request(self, data: Any) -> dict[str, Any]:
        """Send a list tasks request."""
        return await self._send_request("tasks/list", data)

    async def _send_get_task_request(self, data: Any) -> dict[str, Any]:
        """Send a get task request."""
        return await self._send_request("tasks/get", data)

    async def _send_get_task_payload_request(self, data: Any) -> dict[str, Any]:
        """Send a get task payload request."""
        return await self._send_request("tasks/result", data)

    async def _send_cancel_task_request(self, data: Any) -> dict[str, Any]:
        """Send a cancel task request."""
        return await self._send_request("tasks/cancel", data)

    async def _send_ping_request(self, data: Any) -> dict[str, Any]:
        """Send a ping request."""
        return await self._send_request("ping", data)

    async def _send_request(self, method: str, data: Any) -> dict[str, Any]:
        return await self.transport.send_request(method, self._extract_params(data))

    async def _send_generic_request(self, data: Any) -> dict[str, Any]:
        """Send a generic JSON-RPC request."""
        method = data.get("method") if isinstance(data, dict) else None
        if not isinstance(method, str) or not method:
            method = "unknown"
        params = self._extract_params(data)
        return await self.transport.send_request(method, params)

    async def shutdown(self) -> None:
        """Shutdown the protocol client."""
        return None


def _response_shape_signature(response: Any) -> str | None:
    if response is None:
        return None
    if isinstance(response, dict):
        keys = ",".join(sorted(response.keys()))
        if "result" in response and isinstance(response.get("result"), dict):
            result_keys = ",".join(sorted(response["result"].keys()))
            return f"dict:{keys}:result[{result_keys}]"
        if "error" in response and isinstance(response.get("error"), dict):
            err_keys = ",".join(sorted(response["error"].keys()))
            return f"dict:{keys}:error[{err_keys}]"
        return f"dict:{keys}"
    if isinstance(response, list):
        return f"list:{len(response)}"
    return f"type:{type(response).__name__}"
