#!/usr/bin/env python3
"""
Unit tests for SeedPool persistence and deduplication.
"""

from pathlib import Path

import pytest

from mcp_fuzzer.fuzz_engine.mutators.seed_pool import SeedPool

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


def test_seed_pool_deduplication(tmp_path: Path):
    storage = tmp_path / "corpus"
    pool = SeedPool(storage_dir=storage, autosave=False)
    seed = {"param": "value"}

    added = pool.add_seed("tool:test", seed, signature="sig-1", score=1.0)
    dup = pool.add_seed("tool:test", seed, signature="sig-1", score=1.0)

    assert added is True
    assert dup is False


def test_seed_pool_persistence_roundtrip(tmp_path: Path):
    storage = tmp_path / "corpus"
    seed = {"param": "value"}

    pool = SeedPool(storage_dir=storage, autosave=True)
    assert pool.add_seed("tool:test", seed, signature="sig-1", score=1.2)

    saved = storage / "tool_test.json"
    assert saved.exists()

    reloaded = SeedPool(storage_dir=storage, autosave=False)
    picked = reloaded.pick_seed("tool:test")
    assert picked == seed
