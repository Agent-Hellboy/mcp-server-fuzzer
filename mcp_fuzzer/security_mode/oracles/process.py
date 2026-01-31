#!/usr/bin/env python3
"""Process side-effect oracle for security mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psutil

from ..policy import SecurityPolicy


_SHELL_NAMES = {
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
}


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str
    cmdline: list[str]
    create_time: float | None


def _safe_cmdline(proc: psutil.Process) -> list[str]:
    try:
        return proc.cmdline()
    except (psutil.Error, OSError):
        return []


def _safe_name(proc: psutil.Process) -> str:
    try:
        return proc.name()
    except (psutil.Error, OSError):
        return ""


def _safe_create_time(proc: psutil.Process) -> float | None:
    try:
        return proc.create_time()
    except (psutil.Error, OSError):
        return None


class ProcessSideEffectOracle:
    """Detects new subprocesses spawned by the server."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def pre_call(self, server_pid: int | None) -> dict[int, ProcessInfo] | None:
        if server_pid is None:
            return None
        try:
            root = psutil.Process(server_pid)
        except (psutil.Error, OSError):
            return None
        procs = [root]
        try:
            procs.extend(root.children(recursive=True))
        except (psutil.Error, OSError):
            pass
        snapshot: dict[int, ProcessInfo] = {}
        for proc in procs:
            try:
                info = ProcessInfo(
                    pid=proc.pid,
                    ppid=proc.ppid() if proc.pid != server_pid else None,
                    name=_safe_name(proc),
                    cmdline=_safe_cmdline(proc),
                    create_time=_safe_create_time(proc),
                )
                snapshot[proc.pid] = info
            except (psutil.Error, OSError):
                continue
        return snapshot

    def post_call(
        self,
        server_pid: int | None,
        pre_snapshot: dict[int, ProcessInfo] | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if server_pid is None or pre_snapshot is None:
            return [], []
        try:
            root = psutil.Process(server_pid)
        except (psutil.Error, OSError):
            return [], []
        procs = [root]
        try:
            procs.extend(root.children(recursive=True))
        except (psutil.Error, OSError):
            pass

        post_snapshot: dict[int, ProcessInfo] = {}
        for proc in procs:
            try:
                info = ProcessInfo(
                    pid=proc.pid,
                    ppid=proc.ppid() if proc.pid != server_pid else None,
                    name=_safe_name(proc),
                    cmdline=_safe_cmdline(proc),
                    create_time=_safe_create_time(proc),
                )
                post_snapshot[proc.pid] = info
            except (psutil.Error, OSError):
                continue

        new_pids = set(post_snapshot.keys()) - set(pre_snapshot.keys())
        oracle_findings: list[dict[str, Any]] = []
        side_effects: list[dict[str, Any]] = []

        for pid in new_pids:
            info = post_snapshot.get(pid)
            if not info:
                continue
            cmd_name = (
                self.policy.normalize_command_tokens(info.cmdline)
                or info.name.lower()
            )
            if cmd_name in self.policy.proc_ignore:
                continue
            is_shell = cmd_name in _SHELL_NAMES

            side_effects.append(
                {
                    "oracle": "process",
                    "type": "new_process",
                    "pid": pid,
                    "name": info.name,
                    "cmdline": info.cmdline,
                    "ppid": info.ppid,
                }
            )

            allowlisted = (
                bool(self.policy.proc_allow)
                and cmd_name in self.policy.proc_allow
            )
            if not allowlisted or is_shell:
                oracle_findings.append(
                    {
                        "oracle": "process",
                        "type": "unexpected_process",
                        "pid": pid,
                        "name": info.name,
                        "cmdline": info.cmdline,
                        "reason": "shell_spawn" if is_shell else "not_allowlisted",
                    }
                )

        return oracle_findings, side_effects


__all__ = ["ProcessSideEffectOracle", "ProcessInfo"]
