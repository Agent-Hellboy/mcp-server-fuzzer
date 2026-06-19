"""Canonical evidence dict keys for findings and run summaries."""

from __future__ import annotations

# Finding.evidence keys
INPUT = "input"
RESULT = "result"
RUNS = "runs"
COUNT = "count"
CRASH = "crash"
PAPER_ARXIV_ID = "paper_arxiv_id"

# Run result payload keys (tool/protocol run dicts)
OUTCOME = "outcome"
ACCEPTED_MALFORMED = "accepted_malformed"
SAFETY_BLOCKED = "safety_blocked"
EXCEPTION = "exception"
ERROR = "error"
SERVER_ERROR = "server_error"
SUCCESS = "success"

__all__ = [
    "ACCEPTED_MALFORMED",
    "COUNT",
    "CRASH",
    "ERROR",
    "EXCEPTION",
    "INPUT",
    "OUTCOME",
    "PAPER_ARXIV_ID",
    "RESULT",
    "RUNS",
    "SAFETY_BLOCKED",
    "SERVER_ERROR",
    "SUCCESS",
]
