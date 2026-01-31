#!/usr/bin/env python3
"""
Unit tests for security-mode policy, oracles, and engine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

import psutil
import pytest

from mcp_fuzzer.security_mode import build_security_policy, SecurityModeEngine
from mcp_fuzzer.security_mode import policy as policy_module
from mcp_fuzzer.security_mode.oracles import (
    FilesystemSideEffectOracle,
    NetworkSideEffectOracle,
    ProcessSideEffectOracle,
    filesystem as filesystem_oracle_module,
    network as network_oracle_module,
    process as process_oracle_module,
)

pytestmark = [pytest.mark.unit, pytest.mark.security_mode]


def test_build_security_policy_normalization(tmp_path):
    config = {
        "security_mode": "full",
        "fs_allow_roots": [str(tmp_path / "allowed")],
        "fs_deny_roots": ["/etc"],
        "repo_root": str(tmp_path / "repo"),
        "workspace_root": str(tmp_path / "workspace"),
        "net_allow_hosts": ["https://allowed.example"],
        "net_deny_by_default": True,
        "proc_allow": ["echo"],
        "proc_ignore": ["sleep"],
    }
    policy = build_security_policy(config)
    assert policy
    assert policy.mode == "full"
    assert policy.allow_roots[0].name == "allowed"
    assert policy.repo_root is not None
    assert policy.workspace_root is not None
    assert "allowed.example" in policy.net_allow_hosts
    assert policy.net_deny_by_default is True
    assert "echo" in policy.proc_allow
    assert policy.is_path_allowed(str(tmp_path / "allowed" / "file.txt"))
    assert not policy.is_path_allowed("/etc/passwd")
    assert policy.is_host_allowed("allowed.example")
    assert not policy.is_host_allowed("evil.example")


class _ProcessStub:
    def __init__(
        self,
        pid: int,
        name: str,
        cmdline: Iterable[str],
        child_pids: Iterable[int],
        manager: "_ProcessTree",
    ):
        self.pid = pid
        self._name = name
        self._cmdline = list(cmdline)
        self._child_pids = list(child_pids)
        self._manager = manager

    def children(self, recursive: bool = True) -> list["_ProcessStub"]:
        return [self._manager.get(pid) for pid in self._child_pids]

    def cmdline(self) -> list[str]:
        return self._cmdline

    def name(self) -> str:
        return self._name

    def create_time(self) -> float:
        return 0.0

    def ppid(self) -> int:
        return 1


class _ProcessTree:
    def __init__(self):
        self._nodes: dict[int, _ProcessStub] = {}

    def add(self, node: _ProcessStub) -> None:
        self._nodes[node.pid] = node

    def get(self, pid: int) -> _ProcessStub:
        return self._nodes[pid]


def test_process_oracle_detects_new_process(monkeypatch):
    policy = build_security_policy(
        {"security_mode": "full", "proc_ignore": ["ignored"], "proc_allow": []}
    )
    assert policy
    oracle = ProcessSideEffectOracle(policy)
    tree = _ProcessTree()
    root = _ProcessStub(
        pid=1, name="server", cmdline=["server"], child_pids=[2], manager=tree
    )
    child = _ProcessStub(
        pid=2, name="worker", cmdline=["worker"], child_pids=[], manager=tree
    )
    tree.add(root)
    tree.add(child)

    monkeypatch.setattr("psutil.Process", lambda pid: tree.get(pid))
    pre_snapshot = oracle.pre_call(1)

    new_child = _ProcessStub(
        pid=3,
        name="sh",
        cmdline=["/bin/sh", "-c", "touch /tmp/evil"],
        child_pids=[],
        manager=tree,
    )
    tree.add(new_child)
    root._child_pids.append(3)

    findings, effects = oracle.post_call(1, pre_snapshot)
    assert any(f["type"] == "unexpected_process" for f in findings)
    assert any(e["type"] == "new_process" for e in effects)


def test_filesystem_oracle_detects_symlink_escape(tmp_path):
    policy = build_security_policy(
        {"security_mode": "minimal", "fs_allow_roots": [str(tmp_path)]}
    )
    assert policy
    oracle = FilesystemSideEffectOracle(policy)
    snapshot = oracle.pre_call()
    (tmp_path / "allowed_file").write_text("ok")
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret")
    if not hasattr(os, "symlink"):
        pytest.skip("symlink not available")
    os.symlink(outside, tmp_path / "escape_link")
    findings, effects = oracle.post_call(snapshot)
    assert any(f["type"] == "symlink_escape" for f in findings)
    assert any(e["type"] == "created" for e in effects)


class _NetConn:
    def __init__(self, laddr, raddr):
        self.laddr = laddr
        self.raddr = raddr
        self.status = "ESTABLISHED"


def test_network_oracle_detects_unexpected_connection(monkeypatch):
    policy = build_security_policy(
        {"security_mode": "full", "net_deny_by_default": True, "net_allow_hosts": []}
    )
    assert policy
    oracle = NetworkSideEffectOracle(policy)
    snapshots = [
        [ _NetConn(("127.0.0.1", 8000), ("127.0.0.1", 9000)) ],
        [ _NetConn(("127.0.0.1", 8000), ("evil.example", 80)) ],
    ]
    snapshot_iter = iter(snapshots)

    class _SnapshotProcess:
        def net_connections(self, kind: str):
            return next(snapshot_iter)

    monkeypatch.setattr("psutil.Process", lambda pid: _SnapshotProcess())
    pre_snapshot = oracle.pre_call(1)
    findings, effects = oracle.post_call(1, pre_snapshot)
    assert any(f["type"] == "unexpected_connection" for f in findings)
    assert any(e["type"] == "outbound_connection" for e in effects)


def test_security_mode_engine_expectations_and_verdicts(tmp_path):
    policy = build_security_policy(
        {
            "security_mode": "full",
            "fs_allow_roots": [str(tmp_path)],
            "net_deny_by_default": True,
        }
    )
    assert policy
    engine = SecurityModeEngine(policy)
    args = {
        "path": str(tmp_path / ".." / "secret.txt"),
        "url": "http://notallowed.example",
        "command": "bash -c 'ls'",
    }
    expectations = engine.pre_call_expectations("test-tool", args)
    assert expectations.path_violation_expected
    assert expectations.network_violation_expected
    assert expectations.command_violation_expected

    findings = [{"oracle": "filesystem", "type": "modified"}]
    verdict = engine.post_call_verdicts(
        success=True,
        exception=None,
        oracle_findings=findings,
        expectations=expectations,
    )
    assert verdict.policy_violations
    assert verdict.semantic_mismatch
    assert verdict.semantic_mismatch["status"] == "forbidden_side_effect"


def test_security_mode_engine_no_findings(tmp_path):
    policy = build_security_policy(
        {
            "security_mode": "minimal",
            "fs_allow_roots": [str(tmp_path)],
            "net_deny_by_default": False,
        }
    )
    engine = SecurityModeEngine(policy)
    expectations = engine.pre_call_expectations("tool", {"benign": "value"})
    verdict = engine.post_call_verdicts(
        success=True,
        exception=None,
        oracle_findings=[],
        expectations=expectations,
    )
    assert verdict.policy_violations == []
    assert verdict.semantic_mismatch is None


def test_security_mode_engine_side_effect_on_error(tmp_path):
    policy = build_security_policy(
        {
            "security_mode": "full",
            "fs_allow_roots": [str(tmp_path)],
            "net_deny_by_default": True,
        }
    )
    engine = SecurityModeEngine(policy)
    expectations = engine.pre_call_expectations("tool", {"command": "npm run build"})
    findings = [{"oracle": "process", "type": "unexpected_process"}]
    verdict = engine.post_call_verdicts(
        success=False,
        exception=RuntimeError("failed"),
        oracle_findings=findings,
        expectations=expectations,
    )
    assert verdict.semantic_mismatch
    assert verdict.semantic_mismatch["status"] == "side_effect_on_error"


def test_policy_normalization_helpers(monkeypatch, tmp_path):
    path = tmp_path / "data"
    path.write_text("content")

    def _raise_resolve(self, strict=False):
        raise OSError("boom")

    monkeypatch.setattr(policy_module.Path, "resolve", _raise_resolve)
    normalized = policy_module._normalize_path(str(path))
    assert normalized.name == "data"

    # Cover host normalization variants
    assert policy_module._normalize_host("") == ""
    long_url = "https://Example.COM:443/path"
    assert policy_module._normalize_host(long_url) == "example.com"
    assert policy_module._normalize_host("[::1]:8080") == "::1"
    assert policy_module._normalize_host("host:1234") == "host"


def test_normalize_command_handles_shlex_error(monkeypatch):
    def _raise_value_error(value):
        raise ValueError("boom")

    monkeypatch.setattr(policy_module.shlex, "split", _raise_value_error)
    assert policy_module._normalize_command("something") == "something"


def test_is_under_any_fallback(monkeypatch, tmp_path):
    inside = tmp_path / "nested"
    inside.mkdir()

    def _raise_attr(self, root):
        raise AttributeError("missing")

    monkeypatch.setattr(policy_module.Path, "is_relative_to", _raise_attr)
    assert policy_module._is_under_any(inside, [tmp_path])


def test_security_policy_path_and_host_checks(tmp_path):
    policy = policy_module.SecurityPolicy(
        mode="full",
        fs_allow_roots=(tmp_path,),
        net_deny_by_default=False,
    )
    assert policy.is_path_allowed(str(tmp_path / "subdir"))
    assert not policy.is_path_allowed("/etc/passwd")
    assert policy.is_host_allowed("example.com")

    strict_policy = policy_module.SecurityPolicy(
        mode="full",
        net_deny_by_default=True,
        net_allow_hosts=("_localhost_",),
    )
    assert strict_policy.is_host_allowed("127.0.0.1")
    assert not strict_policy.is_host_allowed("evil.example")


def test_hash_file_handles_errors_and_limits(monkeypatch, tmp_path):
    target = tmp_path / "file"
    target.write_text("ok")

    orig_stat = filesystem_oracle_module.Path.stat

    def raise_stat(self, *args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(filesystem_oracle_module.Path, "stat", raise_stat)
    assert filesystem_oracle_module._hash_file(target) is None

    def large_stat(self, *args, **kwargs):
        class FakeStat:
            st_size = filesystem_oracle_module._HASH_LIMIT_BYTES + 1

        return FakeStat()

    monkeypatch.setattr(filesystem_oracle_module.Path, "stat", large_stat)
    assert filesystem_oracle_module._hash_file(target) is None
    monkeypatch.setattr(filesystem_oracle_module.Path, "stat", orig_stat)
    assert filesystem_oracle_module._hash_file(target) is not None


def test_filesystem_oracle_detects_removed_and_modified(tmp_path):
    policy = build_security_policy(
        {"security_mode": "full", "fs_allow_roots": [str(tmp_path)]}
    )
    oracle = FilesystemSideEffectOracle(policy)
    deleted = tmp_path / "deleted"
    deleted.write_text("remove me")
    modified = tmp_path / "modified"
    modified.write_text("before")
    snapshot = oracle.pre_call()
    deleted.unlink()
    modified.write_text("after")
    created = tmp_path / "new.txt"
    created.write_text("new")

    findings, effects = oracle.post_call(snapshot)
    assert any(effect["type"] == "deleted" for effect in effects)
    assert any(effect["type"] == "modified" for effect in effects)
    assert any(effect["type"] == "created" for effect in effects)


def test_process_safe_helpers_and_allowlist(monkeypatch):
    class _BrokenProc:
        def cmdline(self):
            raise psutil.Error

        def name(self):
            raise OSError

        def create_time(self):
            raise OSError

    broken = _BrokenProc()
    assert process_oracle_module._safe_cmdline(broken) == []
    assert process_oracle_module._safe_name(broken) == ""
    assert process_oracle_module._safe_create_time(broken) is None

    policy = build_security_policy(
        {"security_mode": "full", "proc_allow": ["worker"], "proc_ignore": []}
    )
    oracle = ProcessSideEffectOracle(policy)
    tree = _ProcessTree()
    root = _ProcessStub(
        pid=1, name="server", cmdline=["server"], child_pids=[2], manager=tree
    )
    allowed_child = _ProcessStub(
        pid=2,
        name="worker",
        cmdline=["worker"],
        child_pids=[],
        manager=tree,
    )
    tree.add(root)
    tree.add(allowed_child)

    monkeypatch.setattr("psutil.Process", lambda pid: tree.get(pid))
    pre_snapshot = oracle.pre_call(1)
    findings, effects = oracle.post_call(1, pre_snapshot)
    assert any(effect["type"] == "new_process" for effect in effects)
    assert findings == []

    # Shell detection
    policy_shell = build_security_policy({"security_mode": "full", "proc_allow": []})
    oracle_shell = ProcessSideEffectOracle(policy_shell)
    shell_child = _ProcessStub(
        pid=3,
        name="bash",
        cmdline=["/bin/bash"],
        child_pids=[],
        manager=tree,
    )
    tree.add(shell_child)
    root._child_pids.append(3)
    findings, _ = oracle_shell.post_call(1, pre_snapshot)
    assert any(f["reason"] == "shell_spawn" for f in findings)


def test_network_helpers_and_oracle(monkeypatch):
    assert network_oracle_module._format_addr(None) == ""
    class Addr:
        ip = "1.2.3.4"
        port = 80

    assert network_oracle_module._format_addr(Addr()) == "1.2.3.4:80"
    assert network_oracle_module._format_addr(("127.0.0.1", 9000)) == "127.0.0.1:9000"
    assert network_oracle_module._remote_host(None) == ""
    assert network_oracle_module._remote_host(("1.2.3.4", 80)) == "1.2.3.4"

    policy = build_security_policy(
        {
            "security_mode": "full",
            "net_deny_by_default": True,
            "net_allow_hosts": ["allowed.example"],
        }
    )
    oracle = NetworkSideEffectOracle(policy)

    class _Conn:
        def __init__(self, laddr, raddr, status="ESTABLISHED"):
            self.laddr = laddr
            self.raddr = raddr
            self.status = status

    snapshots = iter(
        [
            [_Conn(("127.0.0.1", 8000), ("allowed.example", 80))],
            [
                _Conn(("127.0.0.1", 8000), ("allowed.example", 80)),
                _Conn(("127.0.0.1", 8001), ("evil.example", 443)),
            ],
        ]
    )

    class _Proc:
        def net_connections(self, kind):
            return next(snapshots)

    monkeypatch.setattr("psutil.Process", lambda pid: _Proc())
    pre_snapshot = oracle.pre_call(1)
    findings, effects = oracle.post_call(1, pre_snapshot)
    assert any(f["type"] == "unexpected_connection" for f in findings)
    assert any(e["type"] == "outbound_connection" for e in effects)
