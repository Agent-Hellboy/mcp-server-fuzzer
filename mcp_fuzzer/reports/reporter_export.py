"""File export and standardized report generation for ``FuzzerReporter``."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Mapping

from .reporter_snapshot import prepare_snapshot

if TYPE_CHECKING:
    from .reporter import FuzzerReporter


async def generate_final_report(
    reporter: FuzzerReporter,
    *,
    include_safety: bool = True,
) -> str:
    """Generate comprehensive final report and save to file."""
    snapshot = await prepare_snapshot(
        reporter, include_safety=include_safety, finalize=True
    )
    json_filename = f"fuzzing_report_{reporter.session_id}.json"
    reporter.formatter_registry.save(
        "json", snapshot, reporter.output_dir, json_filename
    )

    text_filename = f"fuzzing_report_{reporter.session_id}.txt"
    reporter.formatter_registry.save(
        "text", snapshot, reporter.output_dir, text_filename
    )

    if include_safety and reporter.safety_reporter.has_safety_data():
        safety_filename = (
            reporter.output_dir / f"safety_report_{reporter.session_id}.json"
        )
        reporter.safety_reporter.export_safety_data(str(safety_filename))

    logging.info("Final report generated: %s", json_filename)
    return str(reporter.output_dir / json_filename)


async def generate_standardized_report(
    reporter: FuzzerReporter,
    output_types: list[str] | None = None,
    *,
    include_safety: bool = True,
) -> dict[str, str]:
    """Generate standardized reports using the output protocol."""
    generated_files: dict[str, str] = {}
    snapshot = await prepare_snapshot(
        reporter, include_safety=include_safety, finalize=True
    )

    if output_types is None:
        if reporter.output_types:
            output_types = reporter.output_types
        else:
            output_types = ["fuzzing_results"]
            if include_safety and reporter.safety_reporter.has_safety_data():
                output_types.append("safety_summary")

    if "fuzzing_results" in output_types:
        try:
            filepath = reporter.output_manager.save_fuzzing_snapshot(
                snapshot=snapshot,
                safety_enabled=include_safety,
            )
            generated_files["fuzzing_results"] = filepath
        except Exception as exc:
            logging.error("Failed to generate standardized fuzzing results: %s", exc)

    if "safety_summary" in output_types and include_safety:
        try:
            from .reporter_snapshot import gather_safety_data

            safety_data = snapshot.safety_data or gather_safety_data(
                reporter, True
            )
            filepath = reporter.output_manager.save_safety_summary(safety_data)
            generated_files["safety_summary"] = filepath
        except Exception as exc:
            logging.error("Failed to generate standardized safety summary: %s", exc)

    if "error_report" in output_types:
        try:
            errors = reporter.collector.collect_errors()
            if errors:
                filepath = reporter.output_manager.save_error_report(
                    errors=errors,
                    execution_context=snapshot.metadata.to_dict(),
                )
                generated_files["error_report"] = filepath
        except Exception as exc:
            logging.error("Failed to generate standardized error report: %s", exc)

    return generated_files


async def export_format(
    reporter: FuzzerReporter,
    format_name: str,
    filename: str,
    *,
    title: str | None = None,
    include_safety: bool = False,
) -> str:
    """Export report data to a named format."""
    snapshot = await prepare_snapshot(
        reporter, include_safety=include_safety, finalize=False
    )
    if title is not None and format_name == "html":
        reporter._html_adapter = replace(reporter._html_adapter, title=title)
        reporter.formatter_registry.register("html", reporter._html_adapter)
    return reporter.formatter_registry.save(
        format_name, snapshot, reporter.output_dir, filename
    )


async def export_requested_formats(
    reporter: FuzzerReporter,
    export_targets: Mapping[str, str],
    *,
    include_safety: bool = False,
) -> dict[str, str]:
    """Export all requested named formats and return written file names."""
    exported: dict[str, str] = {}
    for format_name, filename in export_targets.items():
        try:
            exported[format_name] = await export_format(
                reporter,
                format_name,
                filename,
                include_safety=include_safety,
            )
        except Exception as exc:
            logging.error(
                "Failed to export %s report to %s: %s",
                format_name,
                filename,
                exc,
            )
    return exported


__all__ = [
    "export_format",
    "export_requested_formats",
    "generate_final_report",
    "generate_standardized_report",
]
