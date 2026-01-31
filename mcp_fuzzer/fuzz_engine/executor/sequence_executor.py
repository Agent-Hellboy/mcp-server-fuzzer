#!/usr/bin/env python3
"""Execute stateful sequences."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from ...transport.interfaces.rpc_adapter import JsonRpcAdapter
from ..mutators.context import FuzzerContext
from ..mutators.sequence import SequenceDefinition, SequenceStep


class SequenceExecutor:
    """Runs sequences step-by-step and maintains derived context state."""

    def __init__(self, rpc: JsonRpcAdapter):
        self._rpc = rpc

    async def execute_sequence(
        self, sequence: SequenceDefinition, context: FuzzerContext
    ) -> tuple[FuzzerContext, list[dict[str, Any]]]:
        current_context = context
        results: list[dict[str, Any]] = []
        for step in sequence.steps:
            response = await self._rpc.call_tool(step.tool_name, step.args)
            results.append(
                {
                    "label": step.label,
                    "tool": step.tool_name,
                    "response": response,
                }
            )
            current_context = self._update_context(current_context, step)
        return current_context, results

    def _update_context(
        self, context: FuzzerContext, step: SequenceStep
    ) -> FuzzerContext:
        if step.label == "create_file":
            path = step.args.get("path")
            if path:
                return replace(
                    context,
                    created_files=context.created_files + (path,),
                )
        if step.label == "create_symlink":
            link = step.args.get("link") or step.args.get("path")
            target = step.args.get("target")
            if link and target:
                return replace(
                    context,
                    symlink_targets=context.symlink_targets + ((link, target),),
                )
        if step.label == "init_repo":
            repo_path = step.args.get("path")
            if repo_path:
                return replace(
                    context,
                    repo_paths=context.repo_paths + (repo_path,),
                )
        return context
