"""Startup checks that fail fast before a long fuzz run."""

from __future__ import annotations

from pathlib import Path

from ..diagnostics.tool_discovery import ToolDiscoveryFailure, ToolDiscoveryReport
from ..exceptions import ArgumentValidationError


def _probe_writable_directory(path: Path, label: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    probe = path / ".mcp_fuzzer_write_probe"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise ArgumentValidationError(
            f"{label} is not writable: {path} ({exc}). "
            "In Docker, mount the output volume with write permission for the "
            "container user and set --fs-root to a path under that mount."
        ) from exc


def verify_output_paths(
    output_dir: str, fs_root: str | None
) -> ToolDiscoveryReport | None:
    """Ensure report and sandbox directories can be created before fuzzing."""
    try:
        _probe_writable_directory(Path(output_dir), "output-dir")
        if fs_root:
            _probe_writable_directory(Path(fs_root), "fs-root")
    except ArgumentValidationError as exc:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.OUTPUT_NOT_WRITABLE,
            str(exc),
        )
    return None


__all__ = ["verify_output_paths"]
