"""Classify fuzzing-run results into categorized software-issue findings.

This is a black-box post-processor: it reads the per-run result dicts produced
by the tool/protocol clients (args/input, outcome, result payload, response
time, crash context, ...) and reports the distinct classes of issues a fuzzer
can surface in an MCP server. Each detector is independent and additive.

Implemented detectors:
- ``crash``                process terminated abnormally (signal/non-zero exit)
- ``oversized_response``   response exceeded the read cap (resource exhaustion)
- ``hang``                 request timed out (deadlock / infinite loop / ReDoS)
- ``internal_error``       JSON-RPC -32603 / HTTP 500 (unhandled server error)
- ``error_leakage``        stack trace / panic / exception text in output
- ``injection_reflection`` a dangerous input token echoed back verbatim
- ``performance_outlier``  response time far above the per-target median
- ``non_determinism``      identical input produced differing outcomes
- ``accepted_malformed``   server accepted clearly-invalid input without error

Detectors that require capabilities beyond a single black-box run (memory-leak
sampling, auth-bypass comparison) are intentionally out of scope here.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..reports.formatters.common import extract_tool_runs

# Severity ranking used for sorting/reporting.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Patterns that indicate a leaked stack trace / unhandled error in output.
_LEAK_PATTERNS = [
    re.compile(r, re.IGNORECASE)
    for r in (
        r"traceback \(most recent call last\)",
        r"\bpanic:",
        r"goroutine \d+ \[",
        r"\bsegmentation fault\b",
        r"addresssanitizer| undefinedbehaviorsanitizer|\basan\b",
        r"\bnullpointerexception\b|\bnzec\b",
        r"\bunhandled exception\b",
        r"\bstack backtrace\b|rust_backtrace",
        r"\bfatal error\b",
        r"\bcaused by:\b",
    )
]

# Dangerous tokens that, if reflected verbatim from input to output, suggest a
# missing sanitization boundary (path traversal, injection, XSS markers).
_INJECTION_MARKERS = [
    "../../../etc/passwd",
    "<script>",
    "'; DROP TABLE",
    "$(id)",
    "`id`",
    "${jndi:",
    "{{7*7}}",
    "\x00",
]

# Response time multiple over the per-target median that flags an outlier.
_PERF_OUTLIER_FACTOR = 5.0
_PERF_MIN_SAMPLES = 4
_PERF_MIN_SECONDS = 0.5

# Memory-growth detection (RSS samples per target). Conservative to avoid
# flagging normal allocator warm-up: needs a sustained multi-fold increase.
_MEM_MIN_SAMPLES = 8
_MEM_GROWTH_FACTOR = 2.0
_MEM_MIN_DELTA_BYTES = 20 * 1024 * 1024  # 20 MB


@dataclass
class Finding:
    """A single categorized issue discovered during fuzzing."""

    category: str
    severity: str
    kind: str  # "tool" or "protocol"
    target: str
    run: int | None
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "kind": self.kind,
            "target": self.target,
            "run": self.run,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def _iter_runs(
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> Iterable[tuple[str, str, int, dict[str, Any]]]:
    """Yield ``(kind, target, run_index, run_dict)`` across both result sets."""
    for tool_name, entry in (tool_results or {}).items():
        runs, _ = extract_tool_runs(entry)
        for index, run in enumerate(runs):
            if isinstance(run, dict):
                yield "tool", tool_name, index + 1, run
    for protocol_type, runs in (protocol_results or {}).items():
        if isinstance(runs, list):
            for index, run in enumerate(runs):
                if isinstance(run, dict):
                    yield "protocol", protocol_type, index + 1, run


def _run_input(kind: str, run: dict[str, Any]) -> Any:
    return run.get("args") if kind == "tool" else run.get("fuzz_data")


def _response_text(run: dict[str, Any]) -> str:
    """Best-effort serialization of a run's response payload for scanning."""
    parts: list[str] = []
    result = run.get("result")
    if result is not None:
        try:
            parts.append(json.dumps(result, default=str))
        except (TypeError, ValueError):
            parts.append(str(result))
    if run.get("exception"):
        parts.append(str(run.get("exception")))
    crash = run.get("crash")
    if isinstance(crash, dict) and crash.get("stderr_tail"):
        parts.append("\n".join(str(line) for line in crash["stderr_tail"]))
    return "\n".join(parts)


def _jsonrpc_code(run: dict[str, Any]) -> int | None:
    result = run.get("result")
    # protocol results nest the response under result["response"].
    candidates = [result]
    if isinstance(result, dict):
        candidates.append(result.get("response"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            error = candidate.get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), int):
                return error["code"]
    return None


def analyze_findings(
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> list[Finding]:
    """Return all findings detected across the tool and protocol results."""
    findings: list[Finding] = []
    runs = list(_iter_runs(tool_results, protocol_results))

    # Per-(kind,target) accumulators for the cross-run detectors.
    response_times: dict[tuple[str, str], list[float]] = {}
    outcomes_by_input: dict[tuple[str, str, str], set[str]] = {}
    rss_series: dict[tuple[str, str], list[int]] = {}

    for kind, target, run_no, run in runs:
        outcome = run.get("outcome")

        if outcome == "crashed" or run.get("error") == "server_crashed":
            findings.append(
                Finding(
                    "crash",
                    "critical",
                    kind,
                    target,
                    run_no,
                    "Server process terminated abnormally on this input.",
                    {"crash": run.get("crash"), "input": _run_input(kind, run)},
                )
            )
        elif outcome == "oversized_response":
            findings.append(
                Finding(
                    "oversized_response",
                    "high",
                    kind,
                    target,
                    run_no,
                    "Server returned a response exceeding the read cap "
                    "(possible resource exhaustion / DoS).",
                    {"input": _run_input(kind, run)},
                )
            )
        elif outcome == "timeout":
            findings.append(
                Finding(
                    "hang",
                    "high",
                    kind,
                    target,
                    run_no,
                    "Request did not return before the timeout "
                    "(possible deadlock / infinite loop / ReDoS).",
                    {"input": _run_input(kind, run)},
                )
            )
        elif outcome == "accepted_malformed" or run.get("accepted_malformed"):
            findings.append(
                Finding(
                    "accepted_malformed",
                    "medium",
                    kind,
                    target,
                    run_no,
                    "Server accepted clearly-malformed input without an error.",
                    {"input": _run_input(kind, run)},
                )
            )

        code = _jsonrpc_code(run)
        if code == -32603:
            findings.append(
                Finding(
                    "internal_error",
                    "medium",
                    kind,
                    target,
                    run_no,
                    "Server reported JSON-RPC -32603 Internal error "
                    "(an unhandled server-side exception).",
                    {"input": _run_input(kind, run)},
                )
            )

        text = _response_text(run)
        for pattern in _LEAK_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding(
                        "error_leakage",
                        "medium",
                        kind,
                        target,
                        run_no,
                        "Response/stderr leaked a stack trace or unhandled "
                        "error (information disclosure).",
                        {"evidence": pattern.pattern},
                    )
                )
                break

        input_text = ""
        run_input = _run_input(kind, run)
        if run_input is not None:
            try:
                input_text = json.dumps(run_input, default=str)
            except (TypeError, ValueError):
                input_text = str(run_input)
        for marker in _INJECTION_MARKERS:
            if marker in input_text and marker in text:
                findings.append(
                    Finding(
                        "injection_reflection",
                        "high",
                        kind,
                        target,
                        run_no,
                        "A dangerous input token was reflected verbatim in the "
                        "response (missing sanitization boundary).",
                        {"marker": marker},
                    )
                )
                break

        rt = run.get("response_time")
        if isinstance(rt, (int, float)) and rt >= 0:
            response_times.setdefault((kind, target), []).append(float(rt))

        rss = run.get("rss_bytes")
        if isinstance(rss, int) and rss > 0:
            rss_series.setdefault((kind, target), []).append(rss)

        if run_input is not None:
            try:
                input_key = json.dumps(run_input, sort_keys=True, default=str)
            except (TypeError, ValueError):
                input_key = str(run_input)
            outcomes_by_input.setdefault((kind, target, input_key), set()).add(
                str(outcome)
            )

    # Cross-run: performance outliers.
    for (kind, target), times in response_times.items():
        if len(times) < _PERF_MIN_SAMPLES:
            continue
        median = statistics.median(times)
        if median <= 0:
            continue
        worst = max(times)
        if worst >= _PERF_MIN_SECONDS and worst >= median * _PERF_OUTLIER_FACTOR:
            findings.append(
                Finding(
                    "performance_outlier",
                    "low",
                    kind,
                    target,
                    None,
                    f"A response took {worst:.3f}s vs a median of {median:.3f}s "
                    "(possible algorithmic-complexity hot spot).",
                    {"max_seconds": worst, "median_seconds": median},
                )
            )

    # Cross-run: non-determinism (same input, differing outcomes).
    for (kind, target, _input_key), outcomes in outcomes_by_input.items():
        meaningful = {o for o in outcomes if o and o != "None"}
        if len(meaningful) > 1:
            findings.append(
                Finding(
                    "non_determinism",
                    "medium",
                    kind,
                    target,
                    None,
                    "Identical input produced differing outcomes across runs "
                    "(possible state corruption / nondeterministic handling).",
                    {"outcomes": sorted(meaningful)},
                )
            )

    # Cross-run: memory growth / leak (stdio targets with RSS samples).
    for (kind, target), series in rss_series.items():
        if len(series) < _MEM_MIN_SAMPLES:
            continue
        quartile = max(1, len(series) // 4)
        baseline = statistics.median(series[:quartile])
        recent = statistics.median(series[-quartile:])
        if (
            baseline > 0
            and recent >= baseline * _MEM_GROWTH_FACTOR
            and (recent - baseline) >= _MEM_MIN_DELTA_BYTES
        ):
            findings.append(
                Finding(
                    "memory_growth",
                    "medium",
                    kind,
                    target,
                    None,
                    f"Server RSS grew from ~{baseline / 1e6:.1f}MB to "
                    f"~{recent / 1e6:.1f}MB across runs (possible memory leak).",
                    {
                        "baseline_bytes": int(baseline),
                        "recent_bytes": int(recent),
                        "samples": len(series),
                    },
                )
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category))
    return findings


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    """Return a count of findings per category (sorted by severity)."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return counts
