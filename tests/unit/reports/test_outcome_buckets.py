"""Tests for shared outcome bucket summarization."""

from __future__ import annotations

from mcp_fuzzer.reports.formatters.common import summarize_tool_outcomes
from mcp_fuzzer.reports.outcome_buckets import OUTCOME_BUCKET_NAMES


def test_summarize_tool_outcomes_matches_fuzz_outcome_enum_values():
    runs = [
        {"outcome": "server_rejected"},
        {"outcome": "accepted_malformed", "accepted_malformed": True},
        {"outcome": "mutation_failed", "error": "tool_mutation_failed"},
        {"outcome": "oversized_response", "error": "oversized_response"},
        {"safety_blocked": True, "outcome": "safety_blocked"},
        {"exception": "boom"},
        {"outcome": "crashed", "error": "server_crashed"},
    ]
    outcomes = summarize_tool_outcomes(runs)
    assert tuple(outcomes) == OUTCOME_BUCKET_NAMES
    assert outcomes["server_rejected"] == 1
    assert outcomes["accepted_malformed"] == 1
    assert outcomes["anomaly"] == 2
    assert outcomes["safety_blocked"] == 1
    assert outcomes["exceptions"] == 1
    assert outcomes["crashed"] == 1


def test_client_fuzzing_imports_shared_bucket_helper():
    from mcp_fuzzer.reports.outcome_buckets import (
        summarize_tool_outcomes as buckets_fn,
    )

    import mcp_fuzzer.client.tool_client_fuzzing as fuzzing

    assert fuzzing.summarize_tool_outcomes is buckets_fn
