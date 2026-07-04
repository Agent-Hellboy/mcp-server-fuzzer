"""Optional runtime-probe integration for mcp-server-fuzzer.

Bridges the fuzzer to the external ``mcpfz_probe`` sidecar so runtime behavior
(process exec, and later network / file access) triggered by a tool call is
captured by the kernel, attributed to that specific call, and turned into
fuzzer ``Finding`` records.

This is entirely opt-in. Every hook is a no-op unless ``MCP_FUZZER_RUNTIME_PROBE``
is truthy *and* the ``mcpfz_probe`` package plus the sidecar binary are available,
so the fuzzer's normal behavior is unchanged when it is off.

Environment variables:
  MCP_FUZZER_RUNTIME_PROBE=1              enable the probe
  MCPFZ_PROBE_BIN=/path/to/mcpfz-probe   sidecar binary (default: "mcpfz-probe")
  MCPFZ_PROBE_BACKEND=ebpf|fake          backend (default: "ebpf")
  MCPFZ_PROBE_WORKSPACE=<dir>            policy workspace root (default: cwd)
  MCPFZ_PROBE_TMPDIR=<dir>               policy tmp root (default: /tmp)
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _truthy(value: str | None) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class _RuntimeProbe:
    """Process-wide singleton coordinating the sidecar and finding collection."""

    def __init__(self) -> None:
        self._enabled = _truthy(os.environ.get("MCP_FUZZER_RUNTIME_PROBE"))
        self._monitor: Any = None
        self._policy: Any = None
        self._lock = threading.Lock()
        self._findings: list[Any] = []
        self._run_counter: dict[str, int] = {}
        self._generation = 0
        self._started = False

    def enabled(self) -> bool:
        return self._enabled

    def ensure_started(self) -> None:
        if not self._enabled or self._started:
            return
        with self._lock:
            if self._started:
                return
            try:
                from mcpfz_probe import RuntimePolicy, SidecarRuntimeMonitor
            except Exception as exc:  # package not installed
                log.warning("runtime probe disabled: cannot import mcpfz_probe: %s", exc)
                self._enabled = False
                return

            binary = os.environ.get("MCPFZ_PROBE_BIN", "mcpfz-probe")
            backend = os.environ.get("MCPFZ_PROBE_BACKEND", "ebpf")
            raw = os.environ.get("MCPFZ_PROBE_RAW")
            self._monitor = SidecarRuntimeMonitor(
                command=[binary, "--backend", backend],
                raw_path=Path(raw) if raw else None,
            )
            self._policy = RuntimePolicy(
                workspace=Path(os.environ.get("MCPFZ_PROBE_WORKSPACE", os.getcwd())),
                tmpdir=Path(os.environ.get("MCPFZ_PROBE_TMPDIR", "/tmp")),
            )
            try:
                self._monitor.start()
            except Exception as exc:
                log.warning("runtime probe disabled: sidecar failed to start: %s", exc)
                self._enabled = False
                self._monitor = None
                return
            self._started = True
            log.info("runtime probe: sidecar started (%s backend)", backend)

    def set_scope(self, pid: int) -> None:
        if not self._enabled or self._monitor is None:
            return
        try:
            pgid = os.getpgid(pid)
        except Exception:
            pgid = pid
        self._generation += 1
        try:
            self._monitor.set_scope_pgid(pgid, generation=self._generation)
            log.info("runtime probe: scoped to pgid=%s gen=%s", pgid, self._generation)
        except Exception as exc:
            log.warning("runtime probe: set_scope failed: %s", exc)

    def begin(self, tool_name: str) -> str | None:
        if not self._enabled or self._monitor is None:
            return None
        call_id = uuid.uuid4().hex
        try:
            self._monitor.begin_call(call_id, tool_name)
        except Exception as exc:
            log.warning("runtime probe: begin_call failed: %s", exc)
            return None
        return call_id

    def end(self, call_id: str | None, tool_name: str) -> None:
        if not self._enabled or self._monitor is None or call_id is None:
            return
        try:
            from mcpfz_probe import evaluate_events

            summary = self._monitor.end_call(call_id)
            drafts = evaluate_events(summary.events, self._policy)
        except Exception as exc:
            log.warning("runtime probe: end_call failed: %s", exc)
            return
        if not drafts:
            return
        run = self._run_counter.get(tool_name, 0)
        self._run_counter[tool_name] = run + 1
        findings = [self._to_finding(d, tool_name, run) for d in drafts]
        with self._lock:
            self._findings.extend(findings)

    def drain_findings(self) -> list[Any]:
        """Return accumulated per-call findings plus any ambient runtime findings."""
        self._collect_ambient()
        with self._lock:
            out = self._findings
            self._findings = []
        return out

    def stop(self) -> None:
        monitor, self._monitor, self._started = self._monitor, None, False
        if monitor is not None:
            try:
                monitor.stop()
            except Exception:
                pass

    def _collect_ambient(self) -> None:
        """Runtime activity outside any call window (delayed exfil/persistence)."""
        if not self._enabled or self._monitor is None:
            return
        try:
            from mcpfz_probe import evaluate_events

            ambient = self._monitor.ambient_events()
            drafts = evaluate_events(ambient, self._policy)
        except Exception:
            return
        findings = [self._to_finding(d, "<ambient>", None) for d in drafts]
        if findings:
            with self._lock:
                self._findings.extend(findings)

    @staticmethod
    def _to_finding(draft: Any, target: str, run: int | None) -> Any:
        from mcp_fuzzer.diagnostics.model import Finding

        evidence = dict(getattr(draft, "evidence", {}) or {})
        evidence["source"] = "mcpfz-probe"
        return Finding(
            category=draft.category,
            severity=draft.severity,
            kind="tool",
            target=target,
            run=run,
            detail=draft.detail,
            evidence=evidence,
        )


PROBE = _RuntimeProbe()

__all__ = ["PROBE"]
