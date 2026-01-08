#!/usr/bin/env python3
"""
Process registry storage for MCP Fuzzer runtime.
"""

import asyncio
import time
from typing import TypedDict

from .config import ProcessConfig


class ProcessRecord(TypedDict):
    process: asyncio.subprocess.Process
    config: ProcessConfig
    started_at: float
    status: str


class ProcessRegistryTable(dict[int, ProcessRecord]):
    """Typed mapping for processes tracked by ProcessRegistry."""

    def snapshot(self) -> dict[int, ProcessRecord]:
        """Return a shallow copy for safe inspection/testing."""
        return dict(self)


class ProcessRegistry:
    """SINGLE responsibility: Track running processes."""

    def __init__(self) -> None:
        self._processes: ProcessRegistryTable = ProcessRegistryTable()
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def processes(self) -> dict[int, ProcessRecord]:
        return self._processes.snapshot()

    async def register(
        self,
        pid: int,
        process: asyncio.subprocess.Process,
        config: ProcessConfig,
        started_at: float | None = None,
        status: str = "running",
    ) -> None:
        async with self._get_lock():
            self._processes[pid] = {
                "process": process,
                "config": config,
                "started_at": started_at or time.time(),
                "status": status,
            }

    async def unregister(self, pid: int) -> None:
        async with self._get_lock():
            self._processes.pop(pid, None)

    async def get_process(self, pid: int) -> ProcessRecord | None:
        async with self._get_lock():
            record = self._processes.get(pid)
            return dict(record) if record else None  # type: ignore[return-value]

    async def list_pids(self) -> list[int]:
        async with self._get_lock():
            return list(self._processes.keys())

    async def update_status(self, pid: int, status: str) -> None:
        async with self._get_lock():
            if pid in self._processes:
                self._processes[pid]["status"] = status

    async def clear(self) -> None:
        async with self._get_lock():
            self._processes.clear()

    async def snapshot(self) -> dict[int, ProcessRecord]:
        """Return a shallow copy of the registry under lock."""
        async with self._get_lock():
            return dict(self._processes)

    async def contains(self, pid: int) -> bool:
        """Return True if the pid is currently registered."""
        async with self._get_lock():
            return pid in self._processes

    async def get_process_field(self, pid: int, field: str):
        """Fetch a single field from a process record, or None if missing."""
        async with self._get_lock():
            record = self._processes.get(pid)
            if record is None:
                return None
            return record.get(field)
