from __future__ import annotations

from typing import Any

import pytest

from mcp_fuzzer.client.runtime.pipeline import ClientExecutionPipeline


class FakeClient:
    def __init__(self, tool: dict[str, Any] | None = None):
        self.tool = tool
        self.fuzz_tool_calls: list[tuple[dict[str, Any], int]] = []
        self.fuzz_tool_both_phase_calls: list[tuple[dict[str, Any], int]] = []

    async def get_tool_by_name(self, tool_name: str) -> dict[str, Any] | None:
        if self.tool and self.tool.get("name") == tool_name:
            return self.tool
        return None

    async def fuzz_tool(
        self, tool: dict[str, Any], *, runs: int
    ) -> list[dict[str, Any]]:
        self.fuzz_tool_calls.append((tool, runs))
        return [{"success": True}]

    async def fuzz_tool_both_phases(
        self, tool: dict[str, Any], *, runs_per_phase: int
    ) -> dict[str, Any]:
        self.fuzz_tool_both_phase_calls.append((tool, runs_per_phase))
        return {"realistic": [], "aggressive": []}


@pytest.mark.asyncio
async def test_pipeline_resolves_named_tool_before_fuzzing():
    tool = {"name": "echo", "inputSchema": {"type": "object"}}
    client = FakeClient(tool)
    pipeline = ClientExecutionPipeline(
        client, {"phase": "aggressive", "tool": "echo", "runs": 2}
    )

    result = await pipeline.fuzz_tools()

    assert result == {"echo": {"runs": [{"success": True}]}}
    assert client.fuzz_tool_calls == [(tool, 2)]


@pytest.mark.asyncio
async def test_pipeline_resolves_named_tool_before_two_phase_fuzzing():
    tool = {"name": "echo", "inputSchema": {"type": "object"}}
    client = FakeClient(tool)
    pipeline = ClientExecutionPipeline(
        client, {"phase": "both", "tool": "echo", "runs": 3}
    )

    result = await pipeline.fuzz_tools()

    assert result == {"echo": {"realistic": [], "aggressive": []}}
    assert client.fuzz_tool_both_phase_calls == [(tool, 3)]


@pytest.mark.asyncio
async def test_pipeline_returns_empty_result_for_missing_named_tool():
    client = FakeClient()
    pipeline = ClientExecutionPipeline(
        client, {"phase": "aggressive", "tool": "missing", "runs": 2}
    )

    result = await pipeline.fuzz_tools()

    assert result == {}
    assert client.fuzz_tool_calls == []
