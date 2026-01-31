#!/usr/bin/env python3
"""Network side-effect oracle for security mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import psutil

from ..policy import SecurityPolicy


@dataclass(frozen=True)
class ConnectionInfo:
    laddr: str
    raddr: str
    status: str


def _format_addr(addr: object) -> str:
    if not addr:
        return ""
    if hasattr(addr, "ip") and hasattr(addr, "port"):
        return f"{addr.ip}:{addr.port}"
    if isinstance(addr, tuple) and len(addr) >= 2:
        return f"{addr[0]}:{addr[1]}"
    return str(addr)


def _remote_host(addr: object) -> str:
    if not addr:
        return ""
    if hasattr(addr, "ip"):
        return str(addr.ip)
    if isinstance(addr, tuple) and addr:
        return str(addr[0])
    return str(addr)


class NetworkSideEffectOracle:
    """Detects new outbound network connections."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def pre_call(self, server_pid: int | None) -> set[ConnectionInfo] | None:
        if server_pid is None:
            return None
        try:
            proc = psutil.Process(server_pid)
            conns = proc.net_connections(kind="inet")
        except (psutil.Error, OSError):
            return None
        snapshot = set()
        for conn in conns:
            if not conn.raddr:
                continue
            snapshot.add(
                ConnectionInfo(
                    laddr=_format_addr(conn.laddr),
                    raddr=_format_addr(conn.raddr),
                    status=str(conn.status),
                )
            )
        return snapshot

    def post_call(
        self,
        server_pid: int | None,
        pre_snapshot: set[ConnectionInfo] | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if server_pid is None or pre_snapshot is None:
            return [], []
        try:
            proc = psutil.Process(server_pid)
            conns = proc.net_connections(kind="inet")
        except (psutil.Error, OSError):
            return [], []

        post_snapshot = set()
        for conn in conns:
            if not conn.raddr:
                continue
            post_snapshot.add(
                ConnectionInfo(
                    laddr=_format_addr(conn.laddr),
                    raddr=_format_addr(conn.raddr),
                    status=str(conn.status),
                )
            )

        new_conns = post_snapshot - pre_snapshot
        oracle_findings: list[dict[str, Any]] = []
        side_effects: list[dict[str, Any]] = []

        for conn in new_conns:
            host = _remote_host(conn.raddr)
            side_effects.append(
                {
                    "oracle": "network",
                    "type": "outbound_connection",
                    "remote": conn.raddr,
                    "local": conn.laddr,
                    "status": conn.status,
                }
            )
            if not self.policy.is_host_allowed(host):
                oracle_findings.append(
                    {
                        "oracle": "network",
                        "type": "unexpected_connection",
                        "remote": conn.raddr,
                        "status": conn.status,
                    }
                )

        return oracle_findings, side_effects


__all__ = ["NetworkSideEffectOracle", "ConnectionInfo"]
