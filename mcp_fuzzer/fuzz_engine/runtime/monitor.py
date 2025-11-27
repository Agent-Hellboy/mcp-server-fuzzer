#!/usr/bin/env python3
"""
Process monitoring utilities for MCP Fuzzer runtime.
"""

import asyncio
import logging
from typing import Any

from .registry import ProcessRegistry
from .watchdog import ProcessWatchdog, wait_for_process_exit


class ProcessInspector:
    """SINGLE responsibility: Monitor process health."""

    def __init__(
        self,
        registry: ProcessRegistry,
        watchdog: ProcessWatchdog,
        logger: logging.Logger,
    ) -> None:
        self.registry = registry
        self.watchdog = watchdog
        self._logger = logger

    async def get_status(self, pid: int) -> dict[str, Any] | None:
        process_info = await self.registry.get_process(pid)
        if process_info is None:
            return None

        info_copy = process_info.copy()
        process = info_copy["process"]
        registry_status = info_copy.get("status")

        # Honor explicit registry status (e.g., "stopped") even if the process
        # returncode has been populated by mocks/cleanup.
        if registry_status == "stopped":
            info_copy["status"] = "stopped"
        elif process.returncode is None:
            info_copy["status"] = registry_status or "running"
        else:
            # Return code present means process finished
            info_copy["status"] = "finished"
            info_copy["exit_code"] = process.returncode
        return info_copy

    async def list_processes(self) -> list[dict[str, Any]]:
        pids = await self.registry.list_pids()
        results = await asyncio.gather(
            *(self.get_status(pid) for pid in pids),
            return_exceptions=True,
        )
        filtered: list[dict[str, Any]] = []
        for pid, result in zip(pids, results):
            if isinstance(result, Exception):
                self._logger.warning(
                    "Failed to get status for PID %s: %s", pid, result, exc_info=True
                )
                continue
            if isinstance(result, dict):
                filtered.append(result)
        return filtered

    async def get_statistics(self) -> dict[str, Any]:
        process_stats = await self.list_processes()
        watchdog_stats = await self.watchdog.get_stats()

        status_counts: dict[str, int] = {}
        for proc in process_stats:
            status = proc.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "processes": status_counts,
            "watchdog": watchdog_stats,
            "total_managed": len(process_stats),
        }

    async def cleanup_finished_processes(self) -> int:
        cleaned = 0
        pids = await self.registry.list_pids()
        for pid in pids:
            process_info = await self.registry.get_process(pid)
            if not process_info:
                continue
            process = process_info["process"]
            if process.returncode is not None:
                await self.registry.unregister(pid)
                cleaned += 1

        if cleaned > 0:
            self._logger.debug(f"Cleaned up {cleaned} finished processes")
        return cleaned

    async def wait_for_completion(
        self, pid: int, timeout: float | None = None
    ) -> int | None:
        """Wait for process to complete.
        
        Args:
            pid: Process ID to wait for
            timeout: Optional timeout in seconds. If None, waits indefinitely.
        
        Returns:
            Exit code (int) if process completed, None if:
            - Process not found in registry, or
            - Timeout occurred and process is still running (returncode is None)
        """
        process_info = await self.registry.get_process(pid)
        if not process_info:
            return None

        process = process_info["process"]
        try:
            if timeout is None:
                await wait_for_process_exit(process)
            else:
                await wait_for_process_exit(process, timeout=timeout)
            return process.returncode
        except asyncio.TimeoutError:
            return process.returncode
