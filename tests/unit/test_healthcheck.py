#!/usr/bin/env python3
"""Unit tests for the distroless-safe healthcheck."""

from __future__ import annotations

import json

import pytest
from mcp_fuzzer.client import healthcheck

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


def test_healthcheck_fails_when_schemas_missing(monkeypatch):
    monkeypatch.setattr(healthcheck, "_check_schemas", lambda: False)
    rc = healthcheck.run_healthcheck(verbose=False)
    assert rc == 1


def test_healthcheck_reports_error_json(monkeypatch, capsys):
    monkeypatch.setattr(healthcheck, "_check_schemas", lambda: False)
    rc = healthcheck.main(["--verbose"])
    captured = capsys.readouterr().out.strip()
    assert rc == 1
    data = json.loads(captured)
    assert data["status"] == "error"
    assert "schemas directory missing" in str(data["error"])
