#!/usr/bin/env python3
"""Unit tests for corpus helpers."""

from pathlib import Path

import pytest

from mcp_fuzzer.corpus import build_corpus_root, build_target_id

pytestmark = [pytest.mark.unit]


def test_build_target_id_deterministic():
    target_a = build_target_id("http", "http://localhost:8000/mcp")
    target_b = build_target_id("http", "http://localhost:8000/mcp")
    assert target_a == target_b


def test_build_corpus_root(tmp_path: Path):
    root = build_corpus_root(tmp_path, "http-abc123")
    assert root == tmp_path / "corpus" / "http-abc123"
