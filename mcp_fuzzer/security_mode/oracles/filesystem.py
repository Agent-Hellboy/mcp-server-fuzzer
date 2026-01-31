#!/usr/bin/env python3
"""Filesystem side-effect oracle for security mode."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import os

from ..policy import SecurityPolicy


_HASH_LIMIT_BYTES = 64 * 1024


@dataclass(frozen=True)
class FileInfo:
    path: Path
    mtime: float | None
    size: int | None
    mode: int | None
    is_symlink: bool
    link_target: str | None
    content_hash: str | None


def _hash_file(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > _HASH_LIMIT_BYTES:
        return None
    try:
        h = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _snapshot_root(root: Path) -> dict[str, FileInfo]:
    snapshot: dict[str, FileInfo] = {}
    if not root.exists():
        return snapshot
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        entries = list(dirnames) + list(filenames)
        for name in entries:
            path = Path(dirpath) / name
            try:
                stat = path.lstat()
            except OSError:
                continue
            is_symlink = path.is_symlink()
            link_target = None
            if is_symlink:
                try:
                    link_target = os.readlink(path)
                except OSError:
                    link_target = None
            content_hash = None
            if (not is_symlink) and path.is_file():
                content_hash = _hash_file(path)
            snapshot[str(path)] = FileInfo(
                path=path,
                mtime=stat.st_mtime,
                size=stat.st_size,
                mode=stat.st_mode,
                is_symlink=is_symlink,
                link_target=link_target,
                content_hash=content_hash,
            )
    return snapshot


class FilesystemSideEffectOracle:
    """Detects filesystem modifications under allow roots."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def pre_call(self) -> dict[str, FileInfo] | None:
        if not self.policy.allow_roots:
            return None
        snapshot: dict[str, FileInfo] = {}
        for root in self.policy.allow_roots:
            snapshot.update(_snapshot_root(root))
        return snapshot

    def post_call(
        self,
        pre_snapshot: dict[str, FileInfo] | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if pre_snapshot is None or not self.policy.allow_roots:
            return [], []

        post_snapshot: dict[str, FileInfo] = {}
        for root in self.policy.allow_roots:
            post_snapshot.update(_snapshot_root(root))

        pre_paths = set(pre_snapshot.keys())
        post_paths = set(post_snapshot.keys())
        added = post_paths - pre_paths
        removed = pre_paths - post_paths
        common = pre_paths & post_paths

        oracle_findings: list[dict[str, Any]] = []
        side_effects: list[dict[str, Any]] = []

        for path in added:
            info = post_snapshot[path]
            side_effects.append(
                {
                    "oracle": "filesystem",
                    "type": "created",
                    "path": str(info.path),
                    "is_symlink": info.is_symlink,
                }
            )
            if info.is_symlink:
                resolved = info.path.resolve(strict=False)
                if not self.policy.is_path_allowed(resolved):
                    oracle_findings.append(
                        {
                            "oracle": "filesystem",
                            "type": "symlink_escape",
                            "path": str(info.path),
                            "target": info.link_target,
                            "resolved": str(resolved),
                        }
                    )

        for path in removed:
            side_effects.append(
                {
                    "oracle": "filesystem",
                    "type": "deleted",
                    "path": path,
                }
            )

        for path in common:
            before = pre_snapshot[path]
            after = post_snapshot[path]
            if (
                before.mtime != after.mtime
                or before.size != after.size
                or before.mode != after.mode
                or before.content_hash != after.content_hash
                or before.link_target != after.link_target
            ):
                side_effects.append(
                    {
                        "oracle": "filesystem",
                        "type": "modified",
                        "path": path,
                    }
                )

        return oracle_findings, side_effects


__all__ = ["FilesystemSideEffectOracle", "FileInfo"]
