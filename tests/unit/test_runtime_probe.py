from __future__ import annotations

import builtins
import io
import os
import sys
from types import SimpleNamespace

import pytest

from mcp_fuzzer import runtime_probe
from mcp_fuzzer.runtime_probe import PROBE, RuntimeProbeConfig


pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_runtime_probe_state():
    yield
    PROBE.configure(RuntimeProbeConfig(enabled=False))


class _FakeRuntimeEvent:
    def __init__(self, *, type, call_id=None, data=None):
        self.type = type
        self.call_id = call_id
        self.data = data or {}


class _FakeRuntimePolicy:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _fake_evaluate_events(events, policy):
    categories = {
        "exec": "runtime.exec",
        "connect": "runtime.net_connect",
    }
    return [
        SimpleNamespace(
            category=categories[event.type],
            severity="high",
            detail=f"{event.type} observed",
            evidence=dict(event.data),
        )
        for event in events
        if event.type in categories
    ]


def _install_fake_mcpfz_probe(
    monkeypatch,
    *,
    monitor_cls,
    policy_cls=_FakeRuntimePolicy,
    evaluate_events=_fake_evaluate_events,
):
    module = SimpleNamespace(
        RuntimeEvent=_FakeRuntimeEvent,
        RuntimePolicy=policy_cls,
        SidecarRuntimeMonitor=monitor_cls,
        evaluate_events=evaluate_events,
    )
    monkeypatch.setitem(sys.modules, "mcpfz_probe", module)
    return module


def test_runtime_probe_disabled_by_default(monkeypatch):
    monkeypatch.delenv("MCP_FUZZER_RUNTIME_PROBE", raising=False)
    PROBE._reset_for_tests()

    assert PROBE.enabled() is False
    PROBE.ensure_started()
    assert PROBE.begin("tool") is None


def test_runtime_probe_env_config(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_FUZZER_RUNTIME_PROBE", "1")
    monkeypatch.setenv("MCPFZ_PROBE_BACKEND", "fake")
    monkeypatch.setenv("MCPFZ_PROBE_BIN", "/bin/probe")
    monkeypatch.setenv("MCPFZ_PROBE_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.setenv("MCPFZ_PROBE_TMPDIR", str(tmp_path / "tmp"))
    monkeypatch.setenv("MCPFZ_PROBE_ALLOW_EXEC", "/usr/bin/date,/bin/echo")
    monkeypatch.setenv("MCPFZ_PROBE_ALLOW_HOST", "api.example.com,127.0.0.1:8000")

    config = RuntimeProbeConfig.from_mapping({})

    assert config.enabled is True
    assert config.backend == "fake"
    assert config.binary == "/bin/probe"
    assert config.workspace == tmp_path / "workspace"
    assert config.tmpdir == tmp_path / "tmp"
    assert config.exec_allow == ("/usr/bin/date", "/bin/echo")
    assert config.net_allow == ("api.example.com", "127.0.0.1:8000")


def test_runtime_probe_mapping_overrides_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_FUZZER_RUNTIME_PROBE", "1")
    monkeypatch.setenv("MCPFZ_PROBE_BACKEND", "ebpf")
    monkeypatch.setenv("MCPFZ_PROBE_BIN", "/env/probe")

    config = RuntimeProbeConfig.from_mapping(
        {
            "runtime_probe": False,
            "runtime_probe_backend": "fake",
            "runtime_probe_bin": "/cli/probe",
            "runtime_probe_workspace": str(tmp_path / "workspace"),
            "runtime_probe_tmpdir": str(tmp_path / "tmp"),
            "runtime_probe_allow_exec": ["/usr/bin/date"],
            "runtime_probe_allow_host": ["api.example.com"],
        }
    )

    assert config.enabled is False
    assert config.backend == "fake"
    assert config.binary == "/cli/probe"
    assert config.workspace == tmp_path / "workspace"
    assert config.tmpdir == tmp_path / "tmp"
    assert config.exec_allow == ("/usr/bin/date",)
    assert config.net_allow == ("api.example.com",)


def test_runtime_probe_auto_degrades_to_fake(monkeypatch):
    monkeypatch.setattr(runtime_probe, "_host_supports_ebpf", lambda: False)

    config, warnings = RuntimeProbeConfig(
        enabled=True,
        backend="auto",
    ).validated_for_host(protocol="stdio")

    assert config.enabled is True
    assert config.backend == "fake"
    assert any("auto backend selected fake" in warning for warning in warnings)


def test_runtime_probe_auto_uses_ebpf_when_supported(monkeypatch):
    monkeypatch.setattr(runtime_probe, "_host_supports_ebpf", lambda: True)

    config = RuntimeProbeConfig(enabled=True, backend="auto")

    assert config.resolved_backend == "ebpf"


def test_runtime_probe_explicit_ebpf_disables_when_unsupported(monkeypatch):
    monkeypatch.setattr(runtime_probe, "_host_supports_ebpf", lambda: False)

    config, warnings = RuntimeProbeConfig(
        enabled=True,
        backend="ebpf",
    ).validated_for_host(protocol="stdio")

    assert config.enabled is False
    assert any("ebpf backend requires" in warning for warning in warnings)


def test_runtime_probe_warns_for_non_stdio_transport(monkeypatch):
    monkeypatch.setattr(runtime_probe, "_host_supports_ebpf", lambda: True)

    config, warnings = RuntimeProbeConfig(
        enabled=True,
        backend="fake",
    ).validated_for_host(protocol="http")

    assert config.enabled is True
    assert config.backend == "fake"
    assert any("non-stdio transport" in warning for warning in warnings)


def test_runtime_probe_import_failure_self_disables(monkeypatch):
    real_import = builtins.__import__

    def fail_mcpfz(name, *args, **kwargs):
        if name == "mcpfz_probe":
            raise ImportError("missing probe")
        return real_import(name, *args, **kwargs)

    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))
    monkeypatch.setattr(builtins, "__import__", fail_mcpfz)

    PROBE.ensure_started()

    assert PROBE.enabled() is False


def test_runtime_probe_config_error_self_disables(monkeypatch, caplog):
    def fail_from_mapping(config):
        raise ValueError("bad config")

    monkeypatch.setattr(RuntimeProbeConfig, "from_mapping", fail_from_mapping)
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))

    PROBE.configure_from_mapping({})

    assert PROBE.enabled() is False
    assert "runtime probe config ignored" in caplog.text


def test_runtime_probe_config_logs_preflight_warnings(monkeypatch, caplog):
    monkeypatch.setattr(runtime_probe, "_host_supports_ebpf", lambda: False)

    PROBE.configure_from_mapping(
        {"runtime_probe": True, "runtime_probe_backend": "auto"}
    )

    assert PROBE.enabled() is True
    assert "auto backend selected fake" in caplog.text


def test_runtime_probe_start_failure_self_disables(monkeypatch):
    class StartFailMonitor:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("cannot start")

    _install_fake_mcpfz_probe(monkeypatch, monitor_cls=StartFailMonitor)
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))

    PROBE.ensure_started()

    assert PROBE.enabled() is False
    assert PROBE.begin("tool") is None


def test_runtime_probe_legacy_policy_fallback(monkeypatch, tmp_path):
    class StartedMonitor:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    class LegacyPolicy:
        def __init__(
            self,
            *,
            workspace,
            tmpdir,
            exec_allow=None,
            net_allow=None,
        ):
            if exec_allow is not None or net_allow is not None:
                raise TypeError("old mcpfz_probe")
            self.workspace = workspace
            self.tmpdir = tmpdir

    _install_fake_mcpfz_probe(
        monkeypatch,
        monitor_cls=StartedMonitor,
        policy_cls=LegacyPolicy,
    )
    PROBE.configure(
        RuntimeProbeConfig(
            enabled=True,
            backend="fake",
            workspace=tmp_path,
            exec_allow=("/bin/date",),
            net_allow=("api.example.com",),
        )
    )

    PROBE.ensure_started()

    assert PROBE.enabled() is True
    assert PROBE._policy.workspace == tmp_path


def test_runtime_probe_fail_open_when_monitor_methods_raise(monkeypatch):
    class RaisingMonitor:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def set_scope_pgid(self, *args, **kwargs):
            raise RuntimeError("scope failed")

        def begin_call(self, *args, **kwargs):
            raise RuntimeError("begin failed")

        def end_call(self, *args, **kwargs):
            raise RuntimeError("end failed")

        def ambient_events(self):
            raise RuntimeError("ambient failed")

        def stop(self):
            raise RuntimeError("stop failed")

    _install_fake_mcpfz_probe(monkeypatch, monitor_cls=RaisingMonitor)
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))
    PROBE.ensure_started()

    PROBE.set_scope(999999)
    assert PROBE.begin("tool") is None
    PROBE.end("unknown", "tool")
    assert PROBE.drain_findings() == []
    PROBE.stop()


def test_runtime_probe_set_scope_uses_process_group(monkeypatch):
    monitors = []

    class ScopeMonitor:
        def __init__(self, *args, **kwargs):
            monitors.append(self)

        def start(self):
            pass

        def set_scope_pgid(self, pgid, generation):
            self.scope = (pgid, generation)

        def stop(self):
            pass

    _install_fake_mcpfz_probe(monkeypatch, monitor_cls=ScopeMonitor)
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))
    PROBE.ensure_started()

    PROBE.set_scope(os.getpid())

    assert monitors[0].scope == (os.getpgid(os.getpid()), 1)


def test_runtime_probe_maps_call_and_ambient_findings(monkeypatch, tmp_path):
    monitors = []

    class FakeMonitor:
        def __init__(self, command, raw_path=None):
            self.command = command
            self.raw_path = raw_path
            self.calls = []
            monitors.append(self)

        def start(self):
            self.started = True

        def set_scope_pgid(self, pgid, generation):
            self.scope = (pgid, generation)

        def begin_call(self, call_id, tool_name):
            self.calls.append((call_id, tool_name))

        def end_call(self, call_id):
            return SimpleNamespace(
                events=[
                    _FakeRuntimeEvent(
                        type="exec",
                        call_id=call_id,
                        data={"argv": ["/bin/sh"]},
                    )
                ]
            )

        def ambient_events(self):
            return [
                _FakeRuntimeEvent(
                    type="connect",
                    call_id=None,
                    data={"dst": "203.0.113.7:443"},
                )
            ]

        def stop(self):
            self.stopped = True

    _install_fake_mcpfz_probe(monkeypatch, monitor_cls=FakeMonitor)
    PROBE.configure(
        RuntimeProbeConfig(
            enabled=True,
            backend="fake",
            binary="/tmp/mcpfz-probe",
            workspace=tmp_path,
        )
    )
    PROBE.ensure_started()

    first = PROBE.begin("danger")
    PROBE.end(first, "danger")
    second = PROBE.begin("danger")
    PROBE.end(second, "danger")
    findings = PROBE.drain_findings()

    assert monitors[0].command == ["/tmp/mcpfz-probe", "--backend", "fake"]
    assert [finding.category for finding in findings] == [
        "runtime.exec",
        "runtime.exec",
        "runtime.net_connect",
    ]
    assert [finding.run for finding in findings[:2]] == [0, 1]
    assert findings[0].target == "danger"
    assert findings[0].evidence["source"] == "mcpfz-probe"
    assert findings[0].evidence["owasp_mcp_top_10"] == "MCP05:2025"
    assert findings[0].evidence["owasp_mcp_url"].startswith("https://owasp.org/")
    assert findings[2].target == "<ambient>"
    assert findings[2].run is None


def test_runtime_probe_end_with_no_policy_drafts(monkeypatch):
    class EmptyMonitor:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def begin_call(self, call_id, tool_name):
            pass

        def end_call(self, call_id):
            return SimpleNamespace(events=[])

        def stop(self):
            pass

    _install_fake_mcpfz_probe(
        monkeypatch,
        monitor_cls=EmptyMonitor,
        evaluate_events=lambda events, policy: [],
    )
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))
    PROBE.ensure_started()

    call_id = PROBE.begin("quiet")
    PROBE.end(call_id, "quiet")

    assert PROBE.drain_findings() == []


def test_runtime_probe_handles_end_without_call_id():
    PROBE.configure(RuntimeProbeConfig(enabled=True, backend="fake"))

    PROBE.end(None, "tool")

    assert PROBE.drain_findings() == []


def test_host_supports_ebpf_for_root_linux_x86(monkeypatch):
    monkeypatch.setattr(runtime_probe.sys, "platform", "linux")
    monkeypatch.setattr(runtime_probe.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(runtime_probe.os, "geteuid", lambda: 0)

    assert runtime_probe._host_supports_ebpf() is True


def test_has_cap_bpf_from_proc_status(monkeypatch):
    monkeypatch.setattr(runtime_probe.os, "geteuid", lambda: 1000)

    def fake_open(path, *args, **kwargs):
        assert path == "/proc/self/status"
        return io.StringIO(f"Name:\tpython\nCapEff:\t{1 << 39:x}\n")

    monkeypatch.setattr(builtins, "open", fake_open)

    assert runtime_probe._has_cap_bpf() is True


def test_has_cap_bpf_fail_closed_on_proc_error(monkeypatch):
    monkeypatch.setattr(runtime_probe.os, "geteuid", lambda: 1000)

    def fail_open(*args, **kwargs):
        raise OSError("missing proc")

    monkeypatch.setattr(builtins, "open", fail_open)

    assert runtime_probe._has_cap_bpf() is False


def test_has_cap_bpf_fail_closed_without_cap_eff(monkeypatch):
    monkeypatch.setattr(runtime_probe.os, "geteuid", lambda: 1000)

    def fake_open(path, *args, **kwargs):
        assert path == "/proc/self/status"
        return io.StringIO("Name:\tpython\n")

    monkeypatch.setattr(builtins, "open", fake_open)

    assert runtime_probe._has_cap_bpf() is False
