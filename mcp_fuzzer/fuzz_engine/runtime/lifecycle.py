#!/usr/bin/env python3
"""
Process lifecycle management for MCP Fuzzer runtime.
"""

import asyncio
import logging
import os
import subprocess
from typing import Any

from ...exceptions import MCPError, ProcessStartError, ProcessStopError
from .config import ProcessConfig, merge_env
from .registry import ProcessRecord, ProcessRegistry
from .signals import SignalDispatcher
from .watchdog import ProcessWatchdog, wait_for_process_exit


def _normalize_returncode(value: Any) -> int | None:
    """Return an integer returncode or None, ignore mock objects."""
    if value is None or isinstance(value, int):
        return value
    return None


def _format_output(data: Any) -> str:
    """Convert process output into a readable string."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace").strip()
    if isinstance(data, str):
        return data.strip()
    return str(data).strip()


class ProcessLifecycle:
    """SINGLE responsibility: Start and stop processes."""

    def __init__(
        self,
        watchdog: ProcessWatchdog,
        registry: ProcessRegistry,
        signal_handler: SignalDispatcher,
        logger: logging.Logger,
    ) -> None:
        self.watchdog = watchdog
        self.registry = registry
        self.signal_handler = signal_handler
        self._logger = logger

    async def start(self, config: ProcessConfig) -> asyncio.subprocess.Process:
        """Start a new process asynchronously."""
        cwd = str(config.cwd) if config.cwd is not None else None
        env = merge_env(None, config.env)

        try:
            await self.watchdog.start()
            process = await asyncio.create_subprocess_exec(
                *config.command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=(os.name != "nt"),
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
                ),
            )
            await asyncio.sleep(0.1)

            returncode = _normalize_returncode(process.returncode)
            if returncode is not None:
                stderr = await process.stderr.read()
                stdout = await process.stdout.read()
                error_output = (
                    _format_output(stderr) or _format_output(stdout) or "No output"
                )
                safe_env: dict[str, Any] | str | None = None
                if isinstance(env, dict):
                    safe_env = {"keys": sorted(env.keys())}
                elif env is not None:
                    safe_env = str(env)

                raise ProcessStartError(
                    (
                        f"Process {config.name} exited with code "
                        f"{returncode}: {error_output}"
                    ),
                    context={
                        "command": config.command,
                        "cwd": cwd,
                        "env": safe_env,
                        "returncode": returncode,
                        "stderr": _format_output(stderr),
                        "stdout": _format_output(stdout),
                    },
                )

            await self.registry.register(process.pid, process, config)
            await self.watchdog.update_activity(process.pid)
            self._logger.info(
                f"Started process {process.pid} ({config.name}): "
                f"{' '.join(config.command)}"
            )
            return process

        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to start process {config.name}: {e}")
            raise ProcessStartError(
                f"Failed to start process {config.name}",
                context={
                    "name": config.name,
                    "command": config.command,
                    "cwd": cwd,
                },
            ) from e

    async def stop(self, pid: int, force: bool = False) -> bool:
        """Stop a running process asynchronously."""
        process_info = await self.registry.get_process(pid)
        if not process_info:
            return False

        process = process_info["process"]
        name = process_info["config"].name
        try:
            returncode = _normalize_returncode(process.returncode)
            if returncode is not None:
                self._logger.debug(
                    "Process %s (%s) already exited with code %s",
                    pid,
                    name,
                    returncode,
                )
                await self.registry.update_status(pid, "stopped")
                await self.registry.unregister(pid)
                return True

            if force:
                await self._force_kill_process(pid, process_info)
            else:
                await self._graceful_terminate_process(pid, process_info)

            final_returncode = _normalize_returncode(process.returncode)
            if final_returncode is None:
                if isinstance(process, (asyncio.subprocess.Process, subprocess.Popen)):
                    raise ProcessStopError(
                        f"Process {pid} ({name}) did not exit after stop attempt",
                        context={"pid": pid, "force": force, "name": name},
                    )

                # Treat mock/test doubles as stopped once signals are sent
                process.returncode = 0
                self._logger.debug(
                    "Assuming mock process %s (%s) stopped after signals", pid, name
                )

            await self.registry.update_status(pid, "stopped")
            await self.registry.unregister(pid)
            return True

        except MCPError:
            raise
        except Exception as e:
            self._logger.error(f"Failed to stop process {pid} ({name}): {e}")
            raise ProcessStopError(
                f"Failed to stop process {pid} ({name})",
                context={"pid": pid, "force": force, "name": name},
            ) from e

    async def _force_kill_process(self, pid: int, process_info: ProcessRecord) -> None:
        """Force kill a process."""
        process = process_info["process"]
        name = process_info["config"].name
        await self.signal_handler.send("force", pid, process_info)
        try:
            await wait_for_process_exit(process, timeout=1.0)
        except asyncio.TimeoutError:
            self._logger.warning(
                f"Process {pid} ({name}) didn't respond to kill signal"
            )

    async def _graceful_terminate_process(
        self, pid: int, process_info: ProcessRecord
    ) -> None:
        """Gracefully terminate a process."""
        process = process_info["process"]
        name = process_info["config"].name
        await self.signal_handler.send("timeout", pid, process_info)
        try:
            await wait_for_process_exit(process, timeout=2.0)
            self._logger.info(f"Gracefully stopped process {pid} ({name})")
        except asyncio.TimeoutError:
            self._logger.info(f"Escalating to SIGKILL for process {pid} ({name})")
            await self._force_kill_process(pid, process_info)

    async def stop_all(self, force: bool = False) -> None:
        """Stop all running processes asynchronously."""
        pids = await self.registry.list_pids()
        tasks = [self.stop(pid, force=force) for pid in pids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        failures: list[dict[str, Any]] = []
        for pid, result in zip(pids, results):
            if isinstance(result, Exception):
                failures.append(
                    {"pid": pid, "error": type(result).__name__, "message": str(result)}
                )
            elif result is False:
                failures.append({"pid": pid, "error": None, "message": "not found"})

        if failures:
            raise ProcessStopError(
                "Failed to stop all managed processes",
                context={"failed_processes": failures},
            )
