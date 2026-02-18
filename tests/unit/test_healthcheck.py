#!/usr/bin/env python3
"""Unit tests for the distroless-safe healthcheck."""

from __future__ import annotations

import json

import pytest
from mcp_fuzzer import healthcheck

pytestmark = [pytest.mark.unit]


def test_healthcheck_passes_with_repo_schemas(tmp_path, monkeypatch):
    # Ensure fallback path is used (project schemas on disk)
    rc = healthcheck.run_healthcheck(verbose=False)
    assert rc == 0


def test_healthcheck_emits_json(monkeypatch, capsys, tmp_path):
    rc = healthcheck.main(["--verbose"])
    captured = capsys.readouterr().out.strip()
    assert rc == 0
    data = json.loads(captured)
    assert data["status"] == "ok"
    assert data["schemas_present"] is True
