"""Listing discovery and follow-up fuzzing for observed MCP entities."""

import copy
import random
from typing import Any

from ..protocol_registry import GET_PROMPT_REQUEST, READ_RESOURCE_REQUEST
from ..types import ProtocolFuzzResult
from ..spec_guard.tool_schema import _build_tool_arguments, _tool_task_support


class ProtocolListingsMixin:
    """Mixin for listing fetches and follow-up fuzzing of discovered entities."""

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

    async def _fetch_listed_items(
        self,
        *,
        method: str,
        key: str,
        entity_name: str,
        remember: Any | None = None,
    ) -> list[dict[str, Any]]:
        try:
            result = await self.transport.send_request(method, {})
        except Exception as exc:
            self._logger.warning("Failed to list %s: %s", entity_name, exc)
            return []

        items = [
            item
            for item in self._extract_list_items(result, key)
            if isinstance(item, dict)
        ]
        if remember is not None:
            for item in items:
                remember(item)
        return items

    async def _fetch_listed_resources(self) -> list[dict[str, Any]]:
        return await self._fetch_listed_items(
            method="resources/list",
            key="resources",
            entity_name="resources",
        )

    async def _fetch_listed_prompts(self) -> list[dict[str, Any]]:
        return await self._fetch_listed_items(
            method="prompts/list",
            key="prompts",
            entity_name="prompts",
        )

    async def _fetch_listed_tools(self) -> list[dict[str, Any]]:
        return await self._fetch_listed_items(
            method="tools/list",
            key="tools",
            entity_name="tools",
            remember=self._remember_tool,
        )

    async def _fetch_listed_tasks(self) -> list[dict[str, Any]]:
        return await self._fetch_listed_items(
            method="tasks/list",
            key="tasks",
            entity_name="tasks",
            remember=self._remember_task,
        )

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
            task_support = _tool_task_support(tool)
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
