"""Write per-crash reproduction artifacts.

When a fuzz run terminates the server process abnormally (outcome ``crashed``),
we persist the exact input plus crash context (exit code/signal and a tail of
the server's stderr) to ``<output_dir>/crashes/`` so a maintainer can replay it.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from .formatters.common import extract_tool_runs

logger = logging.getLogger(__name__)


def _is_crash(run: Any) -> bool:
    return (
        isinstance(run, dict)
        and (run.get("outcome") == "crashed" or run.get("error") == "server_crashed")
    )


def collect_crashes(
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Return a normalized list of crash records from tool/protocol results."""
    crashes: list[dict[str, Any]] = []

    for tool_name, entry in (tool_results or {}).items():
        runs, _ = extract_tool_runs(entry)
        for index, run in enumerate(runs):
            if _is_crash(run):
                crashes.append(
                    {
                        "kind": "tool",
                        "target": tool_name,
                        "run": index + 1,
                        "input": run.get("args"),
                        "crash": run.get("crash"),
                        "exception": run.get("exception"),
                    }
                )

    for protocol_type, runs in (protocol_results or {}).items():
        if not isinstance(runs, list):
            continue
        for index, run in enumerate(runs):
            if _is_crash(run):
                crashes.append(
                    {
                        "kind": "protocol",
                        "target": protocol_type,
                        "run": index + 1,
                        "input": run.get("fuzz_data"),
                        "crash": run.get("crash"),
                        "exception": run.get("exception"),
                    }
                )

    return crashes


def write_crash_repros(
    output_dir: str | os.PathLike[str],
    tool_results: dict[str, Any] | None,
    protocol_results: dict[str, Any] | None,
) -> list[Path]:
    """Persist one JSON repro file per crash; return the written paths."""
    crashes = collect_crashes(tool_results, protocol_results)
    if not crashes:
        return []

    crash_dir = Path(output_dir) / "crashes"
    written: list[Path] = []
    try:
        crash_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:  # pragma: no cover - fs edge
        logger.warning("Could not create crash repro directory: %s", exc)
        return []

    for index, record in enumerate(crashes, start=1):
        safe_target = "".join(
            ch if ch.isalnum() or ch in "-_." else "_" for ch in str(record["target"])
        )[:60]
        path = crash_dir / f"crash-{index:03d}-{record['kind']}-{safe_target}.json"
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(record, handle, indent=2, default=str)
            written.append(path)
        except OSError as exc:  # pragma: no cover - fs edge
            logger.warning("Could not write crash repro %s: %s", path, exc)

    return written
