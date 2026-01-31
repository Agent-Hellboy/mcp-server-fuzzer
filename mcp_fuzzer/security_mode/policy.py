#!/usr/bin/env python3
"""Security mode policy normalization and helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
import ipaddress
import os
import shlex

from ..config.core.constants import SAFETY_LOCAL_HOSTS, SAFETY_NO_NETWORK_DEFAULT


_DEFAULT_DENY_ROOTS = (
    "/etc",
    "/bin",
    "/sbin",
    "/usr",
    "/System",
    "/Library",
    "/Applications",
    "/opt",
    "/var",
)


def _normalize_path(path: str | os.PathLike[str] | None) -> Path | None:
    if not path:
        return None
    try:
        return Path(path).expanduser().resolve(strict=False)
    except Exception:
        return Path(path).expanduser()


def _normalize_host(host: str) -> str:
    if not host:
        return ""
    raw = host.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or raw).strip().lower()
    if raw.startswith("[") and "]" in raw:
        return raw[1: raw.index("]")].lower()
    if ":" in raw:
        return raw.split(":", 1)[0].strip().lower()
    return raw


def _normalize_command(command: str) -> str:
    if not command:
        return ""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = [command]
    if not parts:
        return ""
    return Path(parts[0]).name.lower()


def _normalize_command_tokens(tokens: Iterable[str] | None) -> str:
    if not tokens:
        return ""
    first = next(iter(tokens), "")
    if not first:
        return ""
    return Path(first).name.lower()


def _is_under_any(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            if path.is_relative_to(root):
                return True
        except AttributeError:
            # Python <3.9 fallback
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
    return False


@dataclass(frozen=True)
class SecurityPolicy:
    """Normalized security mode policy."""

    mode: str = "off"
    fs_allow_roots: tuple[Path, ...] = field(default_factory=tuple)
    fs_deny_roots: tuple[Path, ...] = field(default_factory=tuple)
    repo_root: Path | None = None
    workspace_root: Path | None = None
    net_allow_hosts: tuple[str, ...] = field(default_factory=tuple)
    net_deny_by_default: bool = SAFETY_NO_NETWORK_DEFAULT
    proc_allow: tuple[str, ...] = field(default_factory=tuple)
    proc_ignore: tuple[str, ...] = field(default_factory=tuple)

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @property
    def allow_roots(self) -> tuple[Path, ...]:
        roots = list(self.fs_allow_roots)
        if self.repo_root:
            roots.append(self.repo_root)
        if self.workspace_root:
            roots.append(self.workspace_root)
        return tuple(dict.fromkeys(roots))

    @property
    def deny_roots(self) -> tuple[Path, ...]:
        if self.fs_deny_roots:
            return self.fs_deny_roots
        return tuple(
            _normalize_path(p)
            for p in _DEFAULT_DENY_ROOTS
            if _normalize_path(p)
        )

    def normalize_command(self, command: str) -> str:
        return _normalize_command(command)

    def normalize_command_tokens(self, tokens: Iterable[str] | None) -> str:
        return _normalize_command_tokens(tokens)

    def is_host_allowed(self, host: str) -> bool:
        if not self.net_deny_by_default:
            return True
        norm_host = _normalize_host(host)
        if not norm_host:
            return False
        try:
            ip = ipaddress.ip_address(norm_host)
            if ip.is_loopback:
                return True
        except ValueError:
            pass
        allowed = set(_normalize_host(h) for h in self.net_allow_hosts)
        allowed |= {h.lower() for h in SAFETY_LOCAL_HOSTS}
        return norm_host in allowed

    def is_path_allowed(self, path: str | os.PathLike[str]) -> bool:
        resolved = _normalize_path(path)
        if resolved is None:
            return False
        allow_roots = self.allow_roots
        if allow_roots:
            return _is_under_any(resolved, allow_roots)
        deny_roots = self.deny_roots
        if deny_roots and _is_under_any(resolved, deny_roots):
            return False
        return True


def build_security_policy(config: dict[str, object]) -> SecurityPolicy | None:
    mode = str(config.get("security_mode", "off") or "off").lower()
    if mode == "off":
        return None

    def _as_list(value: object | None) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value if v is not None]
        return [str(value)]

    fs_allow_roots = tuple(
        filter(
            None,
            (_normalize_path(p) for p in _as_list(config.get("fs_allow_roots"))),
        )
    )
    fs_deny_roots = tuple(
        filter(
            None,
            (_normalize_path(p) for p in _as_list(config.get("fs_deny_roots"))),
        )
    )
    repo_root = _normalize_path(config.get("repo_root"))
    workspace_root = _normalize_path(
        config.get("workspace_root") or config.get("fs_root")
    )

    net_allow_hosts = tuple(
        _normalize_host(h)
        for h in _as_list(config.get("net_allow_hosts"))
    )
    net_deny_by_default = config.get("net_deny_by_default")
    if net_deny_by_default is None:
        net_deny_by_default = SAFETY_NO_NETWORK_DEFAULT

    proc_allow = tuple(
        _normalize_command(cmd) for cmd in _as_list(config.get("proc_allow"))
    )
    proc_ignore = tuple(
        _normalize_command(cmd) for cmd in _as_list(config.get("proc_ignore"))
    )

    return SecurityPolicy(
        mode=mode,
        fs_allow_roots=fs_allow_roots,
        fs_deny_roots=fs_deny_roots,
        repo_root=repo_root,
        workspace_root=workspace_root,
        net_allow_hosts=net_allow_hosts,
        net_deny_by_default=bool(net_deny_by_default),
        proc_allow=proc_allow,
        proc_ignore=proc_ignore,
    )


__all__ = ["SecurityPolicy", "build_security_policy"]
