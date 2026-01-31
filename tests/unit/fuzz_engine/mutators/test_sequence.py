#!/usr/bin/env python3
"""
Tests for stateful sequence mutator/executor.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_fuzzer.fuzz_engine.executor.sequence_executor import SequenceExecutor
from mcp_fuzzer.fuzz_engine.mutators.context import FuzzerContext
from mcp_fuzzer.fuzz_engine.mutators.sequence import (
    SequenceDefinition,
    SequenceMutator,
    SequenceStep,
)

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


class _DummyRpc:
    async def call_tool(
        self, tool_name: str, args: dict[str, object]
    ) -> dict[str, object]:
        return {"tool": tool_name, "args": args}


def test_sequence_mutator_builds_sequences(tmp_path):
    tools = [
        {"name": "CreateFileTool"},
        {"name": "ReadFileTool"},
        {"name": "SymlinkHelper"},
        {"name": "RepoExecutor"},
    ]
    context = FuzzerContext(corpus_dir=tmp_path)
    mutator = SequenceMutator(tools, context)
    sequences = mutator.build_sequences()
    assert any(seq.name == "create_file_then_read" for seq in sequences)
    assert any(seq.name == "symlink_escape_probe" for seq in sequences)
    assert any(seq.name == "repo_init_and_diff" for seq in sequences)


@pytest.mark.asyncio
async def test_sequence_executor_updates_context(tmp_path):
    rpc = _DummyRpc()
    executor = SequenceExecutor(rpc)
    context = FuzzerContext(corpus_dir=tmp_path)
    steps = (
        SequenceStep(
            tool_name="SampleTool",
            args={"path": str(tmp_path / "probe.txt"), "contents": "payload"},
            label="create_file",
        ),
        SequenceStep(
            tool_name="SampleTool",
            args={"path": str(tmp_path / "probe.txt")},
            label="read_file",
        ),
        SequenceStep(
            tool_name="SampleTool",
            args={
                "link": str(tmp_path / "link.txt"),
                "target": "/etc/passwd",
            },
            label="create_symlink",
        ),
        SequenceStep(
            tool_name="SampleTool",
            args={"path": str(tmp_path / "repo"), "command": "git init"},
            label="init_repo",
        ),
    )
    sequence = SequenceDefinition(name="dummy", steps=steps)
    new_context, results = await executor.execute_sequence(sequence, context)
    assert len(results) == len(steps)
    assert str(tmp_path / "probe.txt") in new_context.created_files
    assert (str(tmp_path / "link.txt"), "/etc/passwd") in new_context.symlink_targets
    assert str(tmp_path / "repo") in new_context.repo_paths


def test_sequence_mutator_with_no_tools(tmp_path):
    context = FuzzerContext(corpus_dir=tmp_path)
    mutator = SequenceMutator([], context)
    assert mutator.build_sequences() == []


@pytest.mark.asyncio
async def test_sequence_executor_empty_sequence(tmp_path):
    rpc = _DummyRpc()
    executor = SequenceExecutor(rpc)
    context = FuzzerContext(corpus_dir=tmp_path)
    sequence = SequenceDefinition(name="empty", steps=())
    new_context, results = await executor.execute_sequence(sequence, context)
    assert results == []
    assert new_context == context
