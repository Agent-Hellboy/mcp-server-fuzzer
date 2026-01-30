#!/usr/bin/env python3
"""Corpus helpers for feedback-guided fuzzing."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import os


def default_fs_root() -> Path:
    return Path(os.getenv("MCP_FUZZER_FS_ROOT", os.path.expanduser("~/.mcp_fuzzer")))


def build_target_id(protocol: str, endpoint: str) -> str:
    normalized_protocol = protocol.lower()
    raw = f"{normalized_protocol}::{endpoint}".lower()
    digest = sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{normalized_protocol}-{digest}"


def build_corpus_root(fs_root: str | Path | None, target_id: str) -> Path:
    root = Path(fs_root) if fs_root else default_fs_root()
    return root / "corpus" / target_id
