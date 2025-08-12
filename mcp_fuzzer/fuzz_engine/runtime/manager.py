#!/usr/bin/env python3
"""
Process Manager for MCP Fuzzer Runtime

This module provides process management functionality with non-blocking
async operations.
"""

import asyncio
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .watchdog import ProcessWatchdog, WatchdogConfig


@dataclass
class ProcessConfig:
    """Configuration for a managed process."""

    command: List[str]
    cwd: Optional[Union[str, Path]] = None
    env: Optional[Dict[str, str]] = None
    timeout: float = 30.0
    auto_kill: bool = True
    name: str = "unknown"
    activity_callback: Optional[Callable[[], float]] = None


class ProcessManager:
    """Manages processes with non-blocking async operations."""

    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the process manager."""
        self.config = config or WatchdogConfig()
        self.watchdog = ProcessWatchdog(self.config)
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._logger = logging.getLogger(__name__)
        self._loop = None  # Initialize lazily when needed

    def _get_loop(self):
        """Get the event loop, initializing it if needed."""
        if self._loop is None:
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                # Create a new event loop if none exists
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    async def start_process(self, config: ProcessConfig) -> subprocess.Popen:
        """Start a new process asynchronously."""
        try:
            # Ensure watchdog monitoring is running
            try:
                self.watchdog.start()
            except Exception:
                pass
            # Start the process in a thread pool to avoid blocking
            process = await self._get_loop().run_in_executor(
                None, self._start_process_sync, config
            )

            # Register with watchdog
            self.watchdog.register_process(
                process.pid, process, config.activity_callback, config.name
            )

            # Store process info
            async with self._lock:
                self._processes[process.pid] = {
                    "process": process,
                    "config": config,
                    "started_at": time.time(),
                    "status": "running",
                }

            self._logger.info(
                (
                    f"Started process {process.pid} ({config.name}): "
                    f"{' '.join(config.command)}"
                )
            )
            return process

        except Exception as e:
            self._logger.error(f"Failed to start process {config.name}: {e}")
            raise

    def _start_process_sync(self, config: ProcessConfig) -> subprocess.Popen:
        """Synchronous process start (runs in thread pool)."""
        return subprocess.Popen(
            config.command,
            cwd=config.cwd,
            env=config.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )

    async def stop_process(self, pid: int, force: bool = False) -> bool:
        """Stop a running process asynchronously."""
        async with self._lock:
            if pid not in self._processes:
                return False

            process_info = self._processes[pid]
            process = process_info["process"]
            name = process_info["config"].name

        try:
            if force:
                # Force kill
                await self._get_loop().run_in_executor(
                    None, self._force_kill_process, pid, process, name
                )
            else:
                # Graceful termination
                await self._get_loop().run_in_executor(
                    None, self._graceful_terminate_process, pid, process, name
                )

            # Update status to reflect stop intent
            async with self._lock:
                if pid in self._processes:
                    self._processes[pid]["status"] = "stopped"

            # Unregister from watchdog
            self.watchdog.unregister_process(pid)

            return True

        except Exception as e:
            self._logger.error(f"Failed to stop process {pid} ({name}): {e}")
            return False

    def _force_kill_process(
        self, pid: int, process: subprocess.Popen, name: str
    ) -> None:
        """Force kill a process (runs in thread pool)."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                process.kill()
        else:
            process.kill()
        self._logger.info(f"Force killed process {pid} ({name})")

    def _graceful_terminate_process(
        self, pid: int, process: subprocess.Popen, name: str
    ) -> None:
        """Gracefully terminate a process (runs in thread pool)."""
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
            except OSError:
                process.terminate()
        else:
            process.terminate()

        # Give process a short window to terminate gracefully
        try:
            process.wait(timeout=2.0)
            self._logger.info(f"Gracefully stopped process {pid} ({name})")
        except subprocess.TimeoutExpired:
            # Process didn't terminate quickly, mark as stopped anyway
            self._logger.info(
                (
                    f"Process {pid} ({name}) marked as stopped "
                    "(graceful termination sent)"
                )
            )

    async def stop_all_processes(self, force: bool = False) -> None:
        """Stop all running processes asynchronously."""
        # Snapshot PIDs under lock to avoid concurrent mutation during iteration
        async with self._lock:
            pids = list(self._processes.keys())
        tasks = [self.stop_process(pid, force=force) for pid in pids]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def get_process_status(self, pid: int) -> Optional[Dict[str, Any]]:
        """Get status information for a specific process."""
        async with self._lock:
            if pid not in self._processes:
                return None

            process_info = self._processes[pid].copy()
            process = process_info["process"]

            # Add current process state
            if hasattr(process, "returncode"):
                if process.returncode is None:
                    process_info["status"] = "running"
                else:
                    process_info["status"] = "finished"
                    process_info["exit_code"] = process.returncode

            return process_info

    async def list_processes(self) -> List[Dict[str, Any]]:
        """Get a list of all managed processes with their status."""
        # Copy current PIDs under lock, then fetch statuses outside to avoid
        # re-entrant lock acquisition in get_process_status
        async with self._lock:
            pids = list(self._processes.keys())

        results = await asyncio.gather(
            *(self.get_process_status(pid) for pid in pids),
            return_exceptions=True,
        )
        # Filter out None and any exceptions
        filtered: List[Dict[str, Any]] = [r for r in results if isinstance(r, dict)]
        return filtered

    async def wait_for_process(
        self, pid: int, timeout: Optional[float] = None
    ) -> Optional[int]:
        """Wait for a process to complete asynchronously."""
        async with self._lock:
            if pid not in self._processes:
                return None

            process = self._processes[pid]["process"]

        try:
            # Non-blocking wait with timeout
            if timeout is None:
                timeout = 0.1  # Default to very short timeout

            # Run process.wait in thread pool to avoid blocking
            await self._get_loop().run_in_executor(None, process.wait, timeout)
            return process.returncode
        except subprocess.TimeoutExpired:
            # Process didn't complete within timeout, return current status
            return getattr(process, "returncode", None)

    async def update_activity(self, pid: int) -> None:
        """Update activity timestamp for a process."""
        self.watchdog.update_activity(pid)

    async def get_stats(self) -> Dict[str, Any]:
        """Get overall statistics about managed processes."""
        process_stats = await self.list_processes()
        watchdog_stats = self.watchdog.get_stats()

        # Count processes by status
        status_counts = {}
        for proc in process_stats:
            status = proc.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "processes": status_counts,
            "watchdog": watchdog_stats,
            "total_managed": len(process_stats),
        }

    async def cleanup_finished_processes(self) -> int:
        """Remove finished processes from tracking and return count cleaned."""
        cleaned = 0
        async with self._lock:
            pids_to_remove = []
            for pid, process_info in self._processes.items():
                process = process_info["process"]
                if hasattr(process, "returncode") and process.returncode is not None:
                    pids_to_remove.append(pid)

            for pid in pids_to_remove:
                del self._processes[pid]
                self.watchdog.unregister_process(pid)
                cleaned += 1

        if cleaned > 0:
            self._logger.debug(f"Cleaned up {cleaned} finished processes")

        return cleaned

    async def shutdown(self) -> None:
        """Shutdown the process manager and stop all processes."""
        self._logger.info("Shutting down process manager")
        await self.stop_all_processes()
        self.watchdog.stop()

    def __del__(self):
        """Cleanup when the object is destroyed."""
        # Don't try to call async methods in destructor
        # The object will be cleaned up by Python's garbage collector
        pass

    async def send_timeout_signal(self, pid: int, signal_type: str = "timeout") -> bool:
        """Send a timeout signal to a running process asynchronously."""
        async with self._lock:
            if pid not in self._processes:
                return False

            process_info = self._processes[pid]
            process = process_info["process"]
            name = process_info["config"].name

        try:
            if hasattr(process, "returncode") and process.returncode is not None:
                # Process already finished
                return False

            # Send signal in thread pool to avoid blocking
            await self._get_loop().run_in_executor(
                None, self._send_signal_sync, pid, process, name, signal_type
            )

            return True

        except Exception as e:
            self._logger.error(
                f"Failed to send {signal_type} signal to process {pid} ({name}): {e}"
            )
            return False

    def _send_signal_sync(
        self, pid: int, process: subprocess.Popen, name: str, signal_type: str
    ) -> None:
        """Send signal to process (runs in thread pool)."""
        if signal_type == "timeout":
            # Send SIGTERM (graceful termination)
            if os.name != "nt":
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGTERM)
                    self._logger.info(
                        f"Sent SIGTERM timeout signal to process {pid} ({name})"
                    )
                except OSError:
                    process.terminate()
                    self._logger.info(
                        f"Sent terminate timeout signal to process {pid} ({name})"
                    )
            else:
                process.terminate()
                self._logger.info(
                    f"Sent terminate timeout signal to process {pid} ({name})"
                )

        elif signal_type == "force":
            # Send SIGKILL (force kill)
            if os.name != "nt":
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGKILL)
                    self._logger.info(
                        f"Sent SIGKILL force signal to process {pid} ({name})"
                    )
                except OSError:
                    process.kill()
                    self._logger.info(
                        f"Sent kill force signal to process {pid} ({name})"
                    )
            else:
                process.kill()
                self._logger.info(f"Sent kill force signal to process {pid} ({name})")

        elif signal_type == "interrupt":
            # Send SIGINT (interrupt)
            if os.name != "nt":
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGINT)
                    self._logger.info(
                        f"Sent SIGINT interrupt signal to process {pid} ({name})"
                    )
                except OSError:
                    # Failed to signal process group; fall back to terminate
                    process.terminate()
                    self._logger.info(
                        f"Sent terminate interrupt signal to process {pid} ({name})"
                    )
            else:
                process.terminate()
                self._logger.info(
                    f"Sent terminate interrupt signal to process {pid} ({name})"
                )

        else:
            self._logger.warning(f"Unknown signal type: {signal_type}")

    async def send_timeout_signal_to_all(
        self, signal_type: str = "timeout"
    ) -> Dict[int, bool]:
        """Send a timeout signal to all running processes asynchronously."""
        results = {}
        pids = list(self._processes.keys())

        tasks = [self.send_timeout_signal(pid, signal_type) for pid in pids]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        for pid, result in zip(pids, results_list):
            if isinstance(result, Exception):
                results[pid] = False
            else:
                results[pid] = result

        return results

    async def is_process_registered(self, pid: int) -> bool:
        """Check if a process is registered with the watchdog."""
        return self.watchdog.is_process_registered(pid)
