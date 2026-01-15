#!/usr/bin/env python3
"""Tests for shared spec guard helper builders."""

from __future__ import annotations

from mcp_fuzzer.spec_guard import helpers


def test_fail_builds_failure_record():
    spec = {"spec_id": "S-123", "spec_url": "https://spec"}
    record = helpers.fail("fail-id", "failed", spec)
    assert record["id"] == "fail-id"
    assert record["status"] == "FAIL"
    assert record["spec_id"] == "S-123"
    assert record["spec_url"] == "https://spec"


def test_warn_builds_warning_record():
    spec = {"spec_id": "S-321", "spec_url": "https://spec"}
    record = helpers.warn("warn-id", "notice", spec)
    assert record["id"] == "warn-id"
    assert record["status"] == "WARN"
    assert record["spec_url"] == "https://spec"
