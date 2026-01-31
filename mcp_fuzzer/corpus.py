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


SECURITY_MODE_CORPUS: list[str] = [
    "; ls",
    "&& whoami",
    "$(curl http://169.254.169.254)",
    "$(bash -lc \"id\")",
    "`uname -a`",
    "../etc/passwd",
    "..\\..\\windows\\system32",
    "--output=/tmp/pwn",
    "--exec=rm -rf /tmp/target",
    "-c whoami",
    "--config=/etc/passwd",
    "--separator=;",
]


def get_security_mode_corpus() -> list[str]:
    """Return a copy of the security mode corpus seed pool."""
    return list(SECURITY_MODE_CORPUS)
