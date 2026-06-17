#!/usr/bin/env python3
"""Execution pipeline interface for client fuzzing workflows."""

from __future__ import annotations

import logging
from typing import Any, Protocol

from ..fuzzer_client import MCPFuzzerClient


logger = logging.getLogger(__name__)


class ExecutionPipeline(Protocol):
    async def fuzz_tools(self) -> dict[str, Any]: ...
    async def fuzz_protocol(self) -> dict[str, Any]: ...
    async def fuzz_resources(self) -> dict[str, Any]: ...
    async def fuzz_prompts(self) -> dict[str, Any]: ...
    async def fuzz_stateful(self) -> dict[str, Any]: ...


class ClientExecutionPipeline:
    """Default execution pipeline backed by MCPFuzzerClient."""

    def __init__(self, client: MCPFuzzerClient, config: dict[str, Any]) -> None:
        self.client = client
        self.config = config

    async def _resolve_requested_tool(self) -> dict[str, Any] | None:
        tool_name = self.config.get("tool")
        if not tool_name:
            return None
        tool = await self.client.get_tool_by_name(tool_name)
        if tool is None:
            logger.error("Requested tool '%s' was not found on the server", tool_name)
        return tool

    @staticmethod
    def _wrap_tool_results(tool_name: str, payload: Any) -> dict[str, Any]:
        """Normalize single-tool results into the reporter-friendly dict shape."""
        if isinstance(payload, dict) and (
            "runs" in payload
            or "realistic" in payload
            or "aggressive" in payload
            or "error" in payload
        ):
            return {tool_name: payload}
        if isinstance(payload, list):
            return {tool_name: {"runs": payload}}
        return {tool_name: {"runs": []}}

    async def fuzz_tools(self) -> dict[str, Any]:
        config = self.config
        if config.get("phase") == "both":
            if config.get("tool"):
                tool = await self._resolve_requested_tool()
                if tool is None:
                    return {}
                tool_name = tool.get("name", "unknown")
                phases = await self.client.fuzz_tool_both_phases(
                    tool, runs_per_phase=config.get("runs", 10)
                )
                return self._wrap_tool_results(tool_name, phases)
            return await self.client.fuzz_all_tools_both_phases(
                runs_per_phase=config.get("runs", 10)
            )

        if config.get("tool"):
            tool = await self._resolve_requested_tool()
            if tool is None:
                return {}
            tool_name = tool.get("name", "unknown")
            runs = await self.client.fuzz_tool(
                tool, runs=config.get("runs", 10)
            )
            return self._wrap_tool_results(tool_name, runs)
        return await self.client.fuzz_all_tools(
            runs_per_tool=config.get("runs", 10)
        )

    async def fuzz_protocol(self) -> dict[str, Any]:
        config = self.config
        phase = config.get("protocol_phase", "realistic")
        if config.get("protocol_type"):
            protocol_type = config["protocol_type"]
            return {
                protocol_type: await self.client.fuzz_protocol_type(
                    protocol_type,
                    runs=config.get("runs_per_type", 10),
                    phase=phase,
                )
            }
        return await self.client.fuzz_all_protocol_types(
            runs_per_type=config.get("runs_per_type", 10),
            phase=phase,
        )

    async def fuzz_resources(self) -> dict[str, Any]:
        config = self.config
        return await self.client.fuzz_resources(
            runs_per_type=config.get("runs_per_type", 10),
            phase=config.get("protocol_phase", "realistic"),
        )

    async def fuzz_prompts(self) -> dict[str, Any]:
        config = self.config
        return await self.client.fuzz_prompts(
            runs_per_type=config.get("runs_per_type", 10),
            phase=config.get("protocol_phase", "realistic"),
        )

    async def fuzz_stateful(self) -> dict[str, Any]:
        config = self.config
        return {
            "stateful_sequences": await self.client.fuzz_stateful_sequences(
                runs=config.get("stateful_runs", 5),
                phase=config.get("protocol_phase", "realistic"),
            )
        }


__all__ = ["ExecutionPipeline", "ClientExecutionPipeline"]
