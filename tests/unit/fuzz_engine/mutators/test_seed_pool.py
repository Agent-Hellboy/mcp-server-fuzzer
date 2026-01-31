#!/usr/bin/env python3
"""
Unit tests for SeedPool persistence and deduplication.
"""

from pathlib import Path

import pytest

import json

from mcp_fuzzer.fuzz_engine.mutators.seed_pool import SeedPool, _safe_filename

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
    assert reloaded.add_seed("tool:test", seed, signature="sig-1", score=1.0) is False


def test_seed_pool_pick_seed_returns_copy(tmp_path: Path):
    pool = SeedPool(storage_dir=tmp_path, autosave=False)
    seed = {"a": 1}
    assert pool.add_seed("tool:copy", seed, signature="sig", score=1.0)
    picked = pool.pick_seed("tool:copy")
    assert picked == seed
    picked["a"] = 2
    assert seed["a"] == 1


def test_seed_pool_trim_and_weights(tmp_path: Path):
    pool = SeedPool(storage_dir=tmp_path, autosave=False, max_per_key=2)
    pool.add_seed("tool:trim", {"id": 1}, signature="s1", score=0.1)
    pool.add_seed("tool:trim", {"id": 2}, signature="s2", score=2.0)
    pool.add_seed("tool:trim", {"id": 3}, signature="s3", score=3.0)
    remaining = [entry.data["id"] for entry in pool._seeds["tool:trim"]]
    assert sorted(remaining) == [2, 3]


def test_seed_pool_should_reseed_ratio_override(tmp_path: Path):
    pool = SeedPool(storage_dir=tmp_path, autosave=False, reseed_ratio=0.0)
    assert pool.should_reseed(ratio_override=1.0) is True
    assert pool.should_reseed(ratio_override=0.0) is False


def test_seed_pool_load_from_dir_handles_invalid_entries(tmp_path: Path):
    storage = tmp_path / "corpus"
    storage.mkdir(parents=True)
    bad_payload = {
        "key": "tool:bad",
        "entries": [
            {"data": {"x": 1}, "signature": "sig", "score": "bad"},
            {"data": ["not-a-dict"], "signature": "sig2", "score": 1.0},
            "invalid",
        ],
    }
    (storage / "tool_bad.json").write_text(json.dumps(bad_payload))

    pool = SeedPool(storage_dir=storage, autosave=False)
    picked = pool.pick_seed("tool:bad")
    assert picked == {"x": 1}


def test_safe_filename_sanitizes():
    assert _safe_filename("tool:weird/name") == "tool_weird_name"
    assert _safe_filename("...") == "seed"
    assert _safe_filename("a" * 200).startswith("a" * 120)
