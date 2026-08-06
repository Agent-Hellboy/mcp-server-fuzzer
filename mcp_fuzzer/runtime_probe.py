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
  MCPFZ_PROBE_BACKEND=ebpf|fake|auto     backend (default: "ebpf")
  MCPFZ_PROBE_WORKSPACE=<dir>            policy workspace root (default: cwd)
  MCPFZ_PROBE_TMPDIR=<dir>               policy tmp root (default: /tmp)
  MCPFZ_PROBE_RAW=<file>                 optional raw sidecar event log
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import logging
import os
import platform
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_RUNTIME_OWASP_MCP_CATEGORY_IDS = {
    "runtime.exec": "MCP05:2025",
    "runtime.process_spawn": "MCP05:2025",
    "runtime.net_connect": "MCP02:2025",
    "runtime.net_bind": "MCP08:2025",
    "runtime.net_listen": "MCP08:2025",
    "runtime.sensitive_read": "MCP02:2025",
    "runtime.fs_write": "MCP02:2025",
    "runtime.fs_delete": "MCP02:2025",
    "runtime.fs_chmod": "MCP02:2025",
    "runtime.fs_mkdir": "MCP02:2025",
    "runtime.fs_rename": "MCP02:2025",
    "runtime.fs_symlink": "MCP02:2025",
    "runtime.fs_link": "MCP02:2025",
    "runtime.ptrace": "MCP05:2025",
}
_OWASP_MCP_URLS = {
    "MCP02:2025": (
        "https://owasp.org/www-project-mcp-top-10/2025/"
        "MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep"
    ),
    "MCP05:2025": (
        "https://owasp.org/www-project-mcp-top-10/2025/"
        "MCP05-2025%E2%80%93Command-Injection%26Execution"
    ),
    "MCP08:2025": "https://owasp.org/www-project-mcp-top-10/",
}


def _truthy(value: str | None) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _split_env_list(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _resolve_backend(value: str) -> str:
    if value == "auto":
        if _host_supports_ebpf():
            return "ebpf"
        return "fake"
    return value


@dataclass(frozen=True)
class RuntimeProbeConfig:
    enabled: bool = False
    backend: str = "ebpf"
    binary: str = "mcpfz-probe"
    workspace: Path | None = None
    tmpdir: Path = Path("/tmp")
    raw_path: Path | None = None
    exec_allow: tuple[str, ...] = ()
    net_allow: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> "RuntimeProbeConfig":
        raw = os.environ.get("MCPFZ_PROBE_RAW")
        return cls(
            enabled=_truthy(os.environ.get("MCP_FUZZER_RUNTIME_PROBE")),
            backend=os.environ.get("MCPFZ_PROBE_BACKEND", "ebpf"),
            binary=os.environ.get("MCPFZ_PROBE_BIN", "mcpfz-probe"),
            workspace=Path(os.environ["MCPFZ_PROBE_WORKSPACE"])
            if os.environ.get("MCPFZ_PROBE_WORKSPACE")
            else None,
            tmpdir=Path(os.environ.get("MCPFZ_PROBE_TMPDIR", "/tmp")),
            raw_path=Path(raw) if raw else None,
            exec_allow=_split_env_list(os.environ.get("MCPFZ_PROBE_ALLOW_EXEC")),
            net_allow=_split_env_list(os.environ.get("MCPFZ_PROBE_ALLOW_HOST")),
        )

    @classmethod
    def from_mapping(cls, config: dict[str, Any]) -> "RuntimeProbeConfig":
        env = cls.from_env()

        def _value(key: str, fallback: Any) -> Any:
            value = config.get(key)
            return fallback if value is None else value

        workspace = _value("runtime_probe_workspace", env.workspace)
        tmpdir = _value("runtime_probe_tmpdir", env.tmpdir)
        raw_path = _value("runtime_probe_raw_path", env.raw_path)
        return cls(
            enabled=bool(_value("runtime_probe", env.enabled)),
            backend=str(_value("runtime_probe_backend", env.backend)),
            binary=str(_value("runtime_probe_bin", env.binary)),
            workspace=Path(workspace) if workspace else None,
            tmpdir=Path(tmpdir),
            raw_path=Path(raw_path) if raw_path else None,
            exec_allow=tuple(_value("runtime_probe_allow_exec", env.exec_allow) or ()),
            net_allow=tuple(_value("runtime_probe_allow_host", env.net_allow) or ()),
        )

    @property
    def resolved_backend(self) -> str:
        return _resolve_backend(self.backend)

    def validated_for_host(
        self, *, protocol: str | None = None
    ) -> tuple["RuntimeProbeConfig", list[str]]:
        warnings: list[str] = []
        if not self.enabled:
            return self, warnings

        backend = self.resolved_backend
        if self.backend == "auto" and backend == "fake":
            warnings.append(
                "runtime probe: auto backend selected fake because eBPF is not "
                "available on this host"
            )
        if self.backend == "ebpf" and not _host_supports_ebpf():
            warnings.append(
                "runtime probe disabled: ebpf backend requires Linux x86_64 with "
                "root or CAP_BPF"
            )
            return replace(self, enabled=False), warnings
        if protocol and protocol != "stdio":
            warnings.append(
                "runtime probe requested with non-stdio transport; process-group "
                "scoping is only available for stdio targets"
            )
        return replace(self, backend=backend), warnings


class _RuntimeProbe:
    """Process-wide singleton coordinating the sidecar and finding collection."""

    def __init__(self) -> None:
        self._config = RuntimeProbeConfig.from_env()
        self._enabled = self._config.enabled
        self._monitor: Any = None
        self._policy: Any = None
        self._lock = threading.Lock()
        self._findings: list[Any] = []
        self._run_counter: dict[str, int] = {}
        self._generation = 0
        self._started = False

    def enabled(self) -> bool:
        return self._enabled

    def configure(self, config: RuntimeProbeConfig) -> None:
        with self._lock:
            if self._started:
                self.stop()
            self._config = config
            self._enabled = config.enabled
            self._findings = []
            self._run_counter = {}
            self._generation = 0

    def configure_from_mapping(self, config: dict[str, Any]) -> None:
        try:
            probe_config, warnings = RuntimeProbeConfig.from_mapping(
                config
            ).validated_for_host(protocol=config.get("protocol"))
            for warning in warnings:
                log.warning(warning)
            self.configure(probe_config)
        except Exception as exc:
            log.warning("runtime probe config ignored: %s", exc)
            self._enabled = False

    def ensure_started(self) -> None:
        if not self._enabled or self._started:
            return
        with self._lock:
            if self._started:
                return
            try:
                from mcpfz_probe import RuntimePolicy, SidecarRuntimeMonitor
            except Exception as exc:  # package not installed
                log.warning("runtime probe: mcpfz_probe import failed: %s", exc)
                self._enabled = False
                return

            config = self._config
            backend = config.resolved_backend
            self._monitor = SidecarRuntimeMonitor(
                command=[config.binary, "--backend", backend],
                raw_path=config.raw_path,
            )
            policy_kwargs = {
                "workspace": config.workspace or Path(os.getcwd()),
                "tmpdir": config.tmpdir,
                "exec_allow": config.exec_allow,
                "net_allow": config.net_allow,
            }
            try:
                self._policy = RuntimePolicy(**policy_kwargs)
            except TypeError:
                log.warning(
                    "runtime probe: installed mcpfz_probe does not support "
                    "runtime allowlists; continuing without allowlists"
                )
                self._policy = RuntimePolicy(
                    workspace=policy_kwargs["workspace"],
                    tmpdir=policy_kwargs["tmpdir"],
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

    def _reset_for_tests(self) -> None:
        self.stop()
        self.configure(RuntimeProbeConfig.from_env())

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
        if draft.category in _RUNTIME_OWASP_MCP_CATEGORY_IDS:
            owasp_id = _RUNTIME_OWASP_MCP_CATEGORY_IDS[draft.category]
            evidence["owasp_mcp_top_10"] = owasp_id
            evidence["owasp_mcp_url"] = _OWASP_MCP_URLS[owasp_id]
        return Finding(
            category=draft.category,
            severity=draft.severity,
            kind="tool",
            target=target,
            run=run,
            detail=draft.detail,
            evidence=evidence,
        )


def _host_supports_ebpf() -> bool:
    return (
        sys.platform.startswith("linux")
        and platform.machine().lower() in {"x86_64", "amd64"}
        and _has_cap_bpf()
    )


def _has_cap_bpf() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status", encoding="utf-8") as status:
            for line in status:
                if line.startswith("CapEff:"):
                    effective = int(line.split(":", 1)[1].strip(), 16)
                    return bool(effective & (1 << 39))
    except Exception:
        return False
    return False


PROBE = _RuntimeProbe()

__all__ = ["PROBE", "RuntimeProbeConfig"]
