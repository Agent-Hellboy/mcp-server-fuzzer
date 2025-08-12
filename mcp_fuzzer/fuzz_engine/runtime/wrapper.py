#!/usr/bin/env python3
"""
Async Process Wrapper for MCP Fuzzer Runtime

This module provides async wrappers around the ProcessManager for
non-blocking operations.
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from .manager import ProcessConfig, ProcessManager


class AsyncProcessWrapper:
    """Async wrapper around ProcessManager for non-blocking operations."""

    def __init__(
        self,
        process_manager: Optional[ProcessManager] = None,
        max_workers: int = 4,
    ):
        """Initialize the async process wrapper."""
        self.process_manager = process_manager or ProcessManager()
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._logger = logging.getLogger(__name__)

    async def start_process(self, config: ProcessConfig) -> Any:
        """Start a process asynchronously."""
        return await self.process_manager.start_process(config)

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        """Stop a process asynchronously."""
        return await self.process_manager.stop_process(pid, force=force)

    async def stop_all_processes(self, force: bool = False) -> None:
        """Stop all processes asynchronously."""
        await self.process_manager.stop_all_processes(force=force)

    async def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get process status asynchronously."""
        return await self.process_manager.get_process_status(pid)

    async def list_processes(self) -> List[Dict[str, Any]]:
        """List all processes asynchronously."""
        return await self.process_manager.list_processes()

    async def wait_for_process(
        self, pid: int, timeout: Optional[float] = None
    ) -> Optional[int]:
        """Wait for a process to complete asynchronously."""
        return await self.process_manager.wait_for_process(pid, timeout=timeout)

    async def update_activity(self, pid: int) -> None:
        """Update process activity asynchronously."""
        await self.process_manager.update_activity(pid)

    async def get_stats(self) -> Dict[str, Any]:
        """Get process statistics asynchronously."""
        return await self.process_manager.get_stats()

    async def cleanup_finished_processes(self) -> int:
        """Clean up finished processes asynchronously."""
        return await self.process_manager.cleanup_finished_processes()

    async def shutdown(self) -> None:
        """Shutdown the wrapper and process manager asynchronously."""
        await self.process_manager.shutdown()
        # Properly shutdown executor without blocking the event loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.executor.shutdown, True)

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        """Send a timeout signal asynchronously."""
        return await self.process_manager.send_timeout_signal(pid, signal_type)

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> Dict[int, bool]:
        """Send timeout signals to all processes asynchronously."""
        return await self.process_manager.send_timeout_signal_to_all(signal_type)

    def __del__(self):
        """Cleanup when the object is destroyed."""
        # Don't try to call async methods in destructor
        # The object will be cleaned up by Python's garbage collector
        pass


class AsyncProcessGroup:
    """Manages a group of async process wrappers."""

    def __init__(self, process_wrapper: Optional[AsyncProcessWrapper] = None):
        """Initialize the async process group."""
        self.process_wrapper = process_wrapper or AsyncProcessWrapper()
        self._logger = logging.getLogger(__name__)

    async def start_multiple_processes(self, configs: List[ProcessConfig]) -> List[Any]:
        """Start multiple processes asynchronously."""
        tasks = [self.process_wrapper.start_process(config) for config in configs]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_multiple_processes(
        self, pids: List[int], force: bool = False
    ) -> List[bool]:
        """Stop multiple processes asynchronously."""
        tasks = [self.process_wrapper.stop_process(pid, force=force) for pid in pids]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def wait_for_multiple_processes(
        self, pids: List[int], timeout: Optional[float] = None
    ) -> List[Optional[int]]:
        """Wait for multiple processes to complete asynchronously."""
        tasks = [
            self.process_wrapper.wait_for_process(pid, timeout=timeout) for pid in pids
        ]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def get_all_process_statuses(self) -> List[Optional[Dict[str, Any]]]:
        """Get statuses for all processes asynchronously."""
        # list_processes already returns statuses for all processes
        return await self.process_wrapper.list_processes()

    async def shutdown(self) -> None:
        """Shutdown the process group asynchronously."""
        await self.process_wrapper.shutdown()

    def __del__(self):
        """Cleanup when the object is destroyed."""
        # Don't try to call async methods in destructor
        # The object will be cleaned up by Python's garbage collector
        pass
