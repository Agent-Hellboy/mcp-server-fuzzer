#!/usr/bin/env python3
"""Stateful sequence mutator helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .context import FuzzerContext


@dataclass(frozen=True)
class SequenceStep:
    """Represents a single tool call within a stateful sequence."""

    tool_name: str
    args: dict[str, Any]
    label: str


@dataclass(frozen=True)
class SequenceDefinition:
    """Description of a multi-step sequence."""

    name: str
    steps: tuple[SequenceStep, ...]


class SequenceMutator:
    """Builds stateful sequences based on the available tool catalog."""

    def __init__(self, tools: Sequence[dict[str, Any]], context: FuzzerContext):
        self.tools = tools
        self.context = context

    def build_sequences(self) -> list[SequenceDefinition]:
        sequences: list[SequenceDefinition] = []
        write_tool = self._match_tool(("write", "create", "touch", "file"))
        read_tool = self._match_tool(("read", "cat", "show", "download"))
        symlink_tool = self._match_tool(("symlink", "link"))
        repo_tool = self._match_tool(("repo", "git", "diff", "log"))
        base_dir = (
            Path(self.context.corpus_dir) if self.context.corpus_dir else Path.cwd()
        )
        seq_dir = base_dir / "security_sequences"
        created_path = str(seq_dir / "created_sequence_file.txt")
        symlink_path = str(seq_dir / "escape_link.txt")
        repo_path = str(seq_dir / "security_repo")

        if write_tool and read_tool:
            sequences.append(
                SequenceDefinition(
                    name="create_file_then_read",
                    steps=(
                        SequenceStep(
                            tool_name=write_tool,
                            args={
                                "path": created_path,
                                "contents": "security-mode sequence probe",
                            },
                            label="create_file",
                        ),
                        SequenceStep(
                            tool_name=read_tool,
                            args={"path": created_path},
                            label="read_file",
                        ),
                    ),
                )
            )

        if symlink_tool and read_tool:
            sequences.append(
                SequenceDefinition(
                    name="symlink_escape_probe",
                    steps=(
                        SequenceStep(
                            tool_name=symlink_tool,
                            args={
                                "link": symlink_path,
                                "target": "/etc/passwd",
                                "path": symlink_path,
                            },
                            label="create_symlink",
                        ),
                        SequenceStep(
                            tool_name=read_tool,
                            args={"path": symlink_path},
                            label="read_symlink",
                        ),
                    ),
                )
            )

        if repo_tool:
            sequences.append(
                SequenceDefinition(
                    name="repo_init_and_diff",
                    steps=(
                        SequenceStep(
                            tool_name=repo_tool,
                            args={
                                "path": repo_path,
                                "command": "git init",
                            },
                            label="init_repo",
                        ),
                        SequenceStep(
                            tool_name=repo_tool,
                            args={
                                "path": repo_path,
                                "command": "git diff --stat",
                            },
                            label="repo_diff",
                        ),
                        SequenceStep(
                            tool_name=repo_tool,
                            args={
                                "path": repo_path,
                                "command": "git log -1",
                            },
                            label="repo_log",
                        ),
                    ),
                )
            )

        return sequences

    def _match_tool(self, keywords: Iterable[str]) -> str | None:
        lower_keywords = [keyword.lower() for keyword in keywords]
        for tool in self.tools:
            name = str(tool.get("name", "")).lower()
            if any(keyword in name for keyword in lower_keywords):
                return tool.get("name")
        return None
