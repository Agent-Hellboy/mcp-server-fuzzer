"""Shared outcome-bucket counters for tool run results."""

from __future__ import annotations

from typing import Any

from .. import evidence_fields as ev

# Mirror ``client.outcomes.FuzzOutcome`` string values without importing client.
SERVER_REJECTED = "server_rejected"
ACCEPTED_MALFORMED_OUTCOME = "accepted_malformed"
TRANSPORT_ERROR = "transport_error"
TIMEOUT = "timeout"
PHASE_FAILED = "phase_failed"
MUTATION_FAILED = "mutation_failed"
OVERSIZED_RESPONSE = "oversized_response"
SAFETY_BLOCKED_OUTCOME = "safety_blocked"
CRASHED = "crashed"

OUTCOME_BUCKET_NAMES = (
    "server_rejected",
    "accepted_malformed",
    "anomaly",
    "crashed",
    "exceptions",
    "safety_blocked",
)

_ANOMALY_OUTCOMES = frozenset(
    {
        TRANSPORT_ERROR,
        TIMEOUT,
        PHASE_FAILED,
        MUTATION_FAILED,
        OVERSIZED_RESPONSE,
    }
)


def _normalized_outcome(run: dict[str, Any]) -> str | None:
    outcome = run.get(ev.OUTCOME)
    if isinstance(outcome, str):
        return outcome
    if outcome is not None and hasattr(outcome, "value"):
        return str(outcome.value)
    return None


def _run_has_exception(run: dict[str, Any]) -> bool:
    if run.get(ev.SAFETY_BLOCKED, False):
        return False
    return bool(run.get(ev.EXCEPTION))


def summarize_tool_outcomes(runs: list[dict[str, Any]]) -> dict[str, int]:
    """Group tool runs by observable fuzzer outcome.

    These buckets intentionally avoid interpreting the upstream tool's business
    result. They only describe how the MCP call behaved from the fuzzer's view.
    """
    buckets = dict.fromkeys(OUTCOME_BUCKET_NAMES, 0)
    for run in runs:
        if not isinstance(run, dict):
            buckets["anomaly"] += 1
            continue

        outcome = _normalized_outcome(run)
        if run.get(ev.SAFETY_BLOCKED, False) or outcome == SAFETY_BLOCKED_OUTCOME:
            buckets["safety_blocked"] += 1
        elif outcome == CRASHED or run.get(ev.ERROR) == "server_crashed":
            buckets["crashed"] += 1
        elif outcome == SERVER_REJECTED:
            buckets["server_rejected"] += 1
        elif outcome == ACCEPTED_MALFORMED_OUTCOME or run.get(ev.ACCEPTED_MALFORMED):
            buckets["accepted_malformed"] += 1
        elif _run_has_exception(run):
            buckets["exceptions"] += 1
        elif (
            run.get(ev.ERROR)
            or run.get(ev.SERVER_ERROR)
            or outcome in _ANOMALY_OUTCOMES
        ):
            buckets["anomaly"] += 1
    return buckets


__all__ = ["OUTCOME_BUCKET_NAMES", "summarize_tool_outcomes"]
