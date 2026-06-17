"""Snapshot and metadata assembly for ``FuzzerReporter``."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .models import FuzzingMetadata, ReportSnapshot

if TYPE_CHECKING:
    from .reporter import FuzzerReporter


def ensure_metadata(reporter: FuzzerReporter) -> FuzzingMetadata:
    """Ensure metadata exists and return it."""
    if reporter._metadata:
        return reporter._metadata
    reporter._metadata = FuzzingMetadata(
        session_id=reporter.session_id,
        mode="unknown",
        protocol="unknown",
        endpoint="unknown",
        runs=0,
        runs_per_type=None,
        fuzzer_version=reporter._fuzzer_version,
        start_time=datetime.now(),
    )
    return reporter._metadata


def finalize_metadata(reporter: FuzzerReporter) -> FuzzingMetadata:
    """Ensure metadata has an end_time and return it."""
    metadata = ensure_metadata(reporter)
    closed = metadata.close()
    reporter._metadata = closed
    return closed


def gather_safety_data(
    reporter: FuzzerReporter, include_safety: bool
) -> dict[str, Any]:
    if not include_safety:
        return {}
    try:
        return reporter.safety_reporter.get_comprehensive_safety_data()
    except Exception as exc:
        logging.error("Failed to gather safety data: %s", exc)
        return {}


async def gather_runtime_data(reporter: FuzzerReporter) -> dict[str, Any]:
    """Gather runtime/process statistics from transport if available."""
    if not reporter._transport:
        return {}

    try:
        if hasattr(reporter._transport, "get_process_stats"):
            stats = await reporter._transport.get_process_stats()
            return {"process_stats": stats}
    except Exception as exc:
        logging.debug("Failed to gather runtime data: %s", exc)

    return {}


async def prepare_snapshot(
    reporter: FuzzerReporter,
    *,
    include_safety: bool,
    finalize: bool,
) -> ReportSnapshot:
    """Create a snapshot of the current report state."""
    metadata = finalize_metadata(reporter) if finalize else ensure_metadata(reporter)
    safety_data = gather_safety_data(reporter, include_safety)
    if include_safety and safety_data:
        reporter.collector.update_safety_data(safety_data)
    runtime_data = await gather_runtime_data(reporter)
    if runtime_data:
        reporter.collector.update_runtime_data(runtime_data)
    return reporter.collector.snapshot(
        metadata,
        safety_data=None,
        runtime_data=None,
        include_safety=include_safety,
    )


__all__ = [
    "ensure_metadata",
    "finalize_metadata",
    "gather_safety_data",
    "gather_runtime_data",
    "prepare_snapshot",
]
