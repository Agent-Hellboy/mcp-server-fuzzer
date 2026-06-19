"""Classify fuzzing-run results into categorized software-issue findings.

Black-box post-processor: reads per-run result dicts from tool/protocol clients
and reports distinct issue classes (crash, hang, leak, injection reflection, …).
Auth-bypass and paper-backed audit checks live under ``mcp_fuzzer.diagnostics``.
"""

from __future__ import annotations

import json
import re
import statistics
from typing import Any, Iterable

from .. import evidence_fields as ev
from ..types import extract_tool_runs
from .model import SEVERITY_ORDER, Finding

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

# Dangerous tokens reflected verbatim suggest a missing sanitization boundary.
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

_PERF_OUTLIER_FACTOR = 5.0
_PERF_MIN_SAMPLES = 4
_PERF_MIN_SECONDS = 0.5

_MEM_MIN_SAMPLES = 8
_MEM_GROWTH_FACTOR = 2.0
_MEM_MIN_DELTA_BYTES = 20 * 1024 * 1024  # 20 MB
_EVIDENCE_RESPONSE_LIMIT = 1200


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


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def _truncated_response(result: Any) -> Any:
    if result is None:
        return None
    try:
        text = json.dumps(result, default=str)
    except (TypeError, ValueError):
        text = str(result)
    if len(text) <= _EVIDENCE_RESPONSE_LIMIT:
        return _jsonable(result)
    return text[:_EVIDENCE_RESPONSE_LIMIT] + "...[truncated]"


def _jsonrpc_code(run: dict[str, Any]) -> int | None:
    result = run.get("result")
    candidates = [result]
    if isinstance(result, dict):
        candidates.append(result.get("response"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            error = candidate.get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), int):
                return error["code"]
    return None


def classify_fuzz_runs(
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> list[Finding]:
    """Return findings detected across tool and protocol fuzz-run results."""
    findings: list[Finding] = []
    runs = list(_iter_runs(tool_results, protocol_results))

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
                    "Server returned a non-error response to an attack-pattern "
                    "or schema-invalid fuzz input.",
                    {
                        "input": _run_input(kind, run),
                        "result": _truncated_response(run.get("result")),
                    },
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

    accepted_malformed = [
        finding for finding in findings if finding.category == "accepted_malformed"
    ]
    other_findings = [
        finding for finding in findings if finding.category != "accepted_malformed"
    ]
    deduped = _dedupe_findings(accepted_malformed) + other_findings
    deduped.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category))
    return deduped


def _serialize_dedupe_key(payload: dict[str, Any]) -> str:
    """Build a stable dedupe key; non-JSON values are stringified explicitly."""
    return json.dumps(payload, sort_keys=True, default=str)


def _finding_dedupe_key(finding: Finding) -> str:
    evidence = dict(finding.evidence or {})
    input_value = evidence.pop(ev.INPUT, None)
    result_value = evidence.pop(ev.RESULT, None)
    return _serialize_dedupe_key(
        {
            "category": finding.category,
            "kind": finding.kind,
            "target": finding.target,
            "detail": finding.detail,
            ev.INPUT: input_value,
            ev.RESULT: result_value,
            "evidence": evidence,
        }
    )


def _merge_duplicate_finding(existing: Finding, incoming: Finding) -> None:
    existing_runs = existing.evidence.setdefault(ev.RUNS, [])
    if existing.run is not None and existing.run not in existing_runs:
        existing_runs.append(existing.run)
    if incoming.run is not None and incoming.run not in existing_runs:
        existing_runs.append(incoming.run)
    existing.evidence[ev.COUNT] = int(existing.evidence.get(ev.COUNT, 1)) + 1
    existing.run = None


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, Finding] = {}
    for finding in findings:
        key = _finding_dedupe_key(finding)
        if key not in grouped:
            grouped[key] = finding
            continue
        _merge_duplicate_finding(grouped[key], finding)

    return list(grouped.values())


def summarize_findings(findings: list[Finding]) -> dict[str, int]:
    """Return a count of findings per category."""
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1
    return counts
