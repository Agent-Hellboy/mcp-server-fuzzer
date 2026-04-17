#!/usr/bin/env python3
"""Tests for shared spec guard helper builders."""

from __future__ import annotations

from mcp_fuzzer.spec_guard import helpers


def test_fail_builds_failure_record():
    spec = {"spec_id": "S-123", "spec_url": "https://spec", "experimental": True}
    record = helpers.fail("fail-id", "failed", spec)
    assert record["id"] == "fail-id"
    assert record["status"] == "FAIL"
    assert record["message"] == "failed"
    assert record["spec_id"] == "S-123"
    assert record["spec_url"] == "https://spec"
    assert record["experimental"] is True


def test_warn_builds_warning_record():
    spec = {"spec_id": "S-321", "spec_url": "https://spec"}
    record = helpers.warn("warn-id", "notice", spec)
    assert record["id"] == "warn-id"
    assert record["status"] == "WARN"
    assert record["message"] == "notice"
    assert record["spec_id"] == "S-321"
    assert record["spec_url"] == "https://spec"


def test_pass_builds_pass_record():
    spec = {"spec_id": "S-999", "spec_url": "https://spec"}
    record = helpers.pass_check("pass-id", "all good", spec)
    assert record["id"] == "pass-id"
    assert record["status"] == "PASS"
    assert record["message"] == "all good"
    assert record["spec_id"] == "S-999"
    assert record["spec_url"] == "https://spec"


def test_spec_variant_preserves_experimental():
    spec = {
        "spec_id": "S-1",
        "spec_url": "https://spec/{version}",
        "experimental": False,
    }
    variant = helpers.spec_variant(spec, spec_id="S-2")
    assert variant["spec_id"] == "S-2"
    assert variant["spec_url"].startswith("https://spec/")
    assert variant["experimental"] is False
