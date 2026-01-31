#!/usr/bin/env python3
"""Run-plan commands for the unified client entrypoint."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
from typing import Any, Protocol

from ...reports import FuzzerReporter
from ..base import MCPFuzzerClient
from .pipeline import ClientExecutionPipeline


@dataclass
class RunContext:
    """Execution context shared across run-plan commands."""

    client: MCPFuzzerClient
    config: dict[str, Any]
    reporter: FuzzerReporter | None
    protocol_phase: str
    pipeline: ClientExecutionPipeline | None = None
    tool_results: dict[str, Any] = field(default_factory=dict)
    protocol_results: dict[str, Any] = field(default_factory=dict)

    def ensure_pipeline(self) -> ClientExecutionPipeline:
        if self.pipeline is None:
            self.pipeline = ClientExecutionPipeline(self.client, self.config)
        return self.pipeline


class RunCommand(Protocol):
    """Command interface for a single run step."""

    name: str

    async def run(self, context: RunContext) -> None: ...


@dataclass
class RunPlan:
    """Explicit list of commands to execute for a given mode."""

    steps: list[RunCommand]

    async def execute(self, context: RunContext) -> None:
        for step in self.steps:
            await step.run(context)


async def _run_spec_guard_if_enabled(
    client: MCPFuzzerClient,
    config: dict[str, Any],
    reporter: FuzzerReporter | None,
) -> None:
    if not config.get("spec_guard", True):
        return
    requested_version = (
        str(config.get("spec_schema_version"))
        if config.get("spec_schema_version") is not None
        else os.getenv("MCP_SPEC_SCHEMA_VERSION")
    )
    checks = await client.run_spec_suite(
        resource_uri=config.get("spec_resource_uri"),
        prompt_name=config.get("spec_prompt_name"),
        prompt_args=config.get("spec_prompt_args"),
    )
    negotiated_version = os.getenv("MCP_SPEC_SCHEMA_VERSION")
    failed = [c for c in checks if str(c.get("status", "")).upper() == "FAIL"]
    logging.info(
        "Spec guard checks completed: %d total, %d failed",
        len(checks),
        len(failed),
    )
    if reporter:
        reporter.add_spec_checks(checks)
        reporter.print_spec_guard_summary(
            checks,
            requested_version=requested_version,
            negotiated_version=negotiated_version,
        )


class SpecGuardCommand:
    name = "spec_guard"

    async def run(self, context: RunContext) -> None:
        await _run_spec_guard_if_enabled(
            context.client, context.config, context.reporter
        )


class ToolsCommand:
    name = "tools"

    async def run(self, context: RunContext) -> None:
        pipeline = context.ensure_pipeline()
        context.tool_results = await pipeline.fuzz_tools()


class ProtocolCommand:
    name = "protocol"

    async def run(self, context: RunContext) -> None:
        pipeline = context.ensure_pipeline()
        context.protocol_results = await pipeline.fuzz_protocol()


class ResourcesCommand:
    name = "resources"

    async def run(self, context: RunContext) -> None:
        pipeline = context.ensure_pipeline()
        context.protocol_results = await pipeline.fuzz_resources()


class PromptsCommand:
    name = "prompts"

    async def run(self, context: RunContext) -> None:
        pipeline = context.ensure_pipeline()
        context.protocol_results = await pipeline.fuzz_prompts()


class StatefulCommand:
    name = "stateful"

    async def run(self, context: RunContext) -> None:
        config = context.config
        if not config.get("stateful", False):
            return
        pipeline = context.ensure_pipeline()
        context.protocol_results.update(await pipeline.fuzz_stateful())


def build_run_plan(mode: str, config: dict[str, Any]) -> RunPlan:
    steps: list[RunCommand] = []
    supported_modes = {"all", "protocol", "resources", "prompts", "tools"}
    if mode not in supported_modes:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "all":
        steps.append(ToolsCommand())
        steps.append(SpecGuardCommand())
        steps.append(ProtocolCommand())
        if config.get("stateful", False):
            steps.append(StatefulCommand())
        return RunPlan(steps)

    if mode in {"protocol", "resources", "prompts"}:
        steps.append(SpecGuardCommand())

    if mode == "tools":
        steps.append(ToolsCommand())
    elif mode == "protocol":
        steps.append(ProtocolCommand())
        if config.get("stateful", False):
            steps.append(StatefulCommand())
    elif mode == "resources":
        steps.append(ResourcesCommand())
        if config.get("stateful", False):
            steps.append(StatefulCommand())
    elif mode == "prompts":
        steps.append(PromptsCommand())
        if config.get("stateful", False):
            steps.append(StatefulCommand())

    return RunPlan(steps)
