"""Tests for findings deduplication helpers."""

from __future__ import annotations

from mcp_fuzzer.diagnostics.classify import _dedupe_findings, _finding_dedupe_key
from mcp_fuzzer.diagnostics.model import Finding
from mcp_fuzzer.evidence_fields import COUNT, INPUT, RESULT, RUNS


class _Weird:
    def __repr__(self) -> str:
        return "weird-object"


def test_dedupe_key_preserves_distinct_non_json_evidence():
    left = Finding(
        "accepted_malformed",
        "medium",
        "tool",
        "t",
        1,
        "detail",
        {INPUT: {"x": 1}, RESULT: {"payload": _Weird()}},
    )
    right = Finding(
        "accepted_malformed",
        "medium",
        "tool",
        "t",
        2,
        "detail",
        {INPUT: {"x": 1}, RESULT: {"payload": object()}},
    )
    assert _finding_dedupe_key(left) != _finding_dedupe_key(right)


def test_dedupe_merges_identical_runs_and_sets_count():
    findings = [
        Finding(
            "accepted_malformed",
            "medium",
            "tool",
            "t",
            1,
            "same",
            {INPUT: {"x": 1}, RESULT: {"ok": True}},
        ),
        Finding(
            "accepted_malformed",
            "medium",
            "tool",
            "t",
            2,
            "same",
            {INPUT: {"x": 1}, RESULT: {"ok": True}},
        ),
    ]
    merged = _dedupe_findings(findings)
    assert len(merged) == 1
    assert merged[0].run is None
    assert merged[0].evidence[COUNT] == 2
    assert merged[0].evidence[RUNS] == [1, 2]
