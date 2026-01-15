#!/usr/bin/env python3
"""
Unit tests for ProcessWatchdog helpers.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_fuzzer.fuzz_engine.runtime.config import WatchdogConfig, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.watchdog import (
    ProcessWatchdog,
    _normalize_activity,
    wait_for_process_exit,
)


@pytest.mark.asyncio
async def test_wait_for_process_exit_sync():
    process = SimpleNamespace(wait=lambda: "done")
    result = await wait_for_process_exit(process)
    assert result == "done"


@pytest.mark.asyncio
async def test_wait_for_process_exit_async():
    async def _wait():
        return "done"

    process = SimpleNamespace(wait=_wait)
    result = await wait_for_process_exit(process)
    assert result == "done"


@pytest.mark.asyncio
async def test_normalize_activity_defaults():
    result = await _normalize_activity(None, 5.0, 10.0, MagicMock())
    assert result == 5.0


@pytest.mark.asyncio
async def test_normalize_activity_bool_and_invalid():
    logger = MagicMock()
    result = await _normalize_activity(lambda: True, 1.0, 10.0, logger)
    assert result == 10.0

    result = await _normalize_activity(lambda: -1, 1.0, 10.0, logger)
    assert result == 1.0


@pytest.mark.asyncio
async def test_scan_once_hung_and_killed():
    registry = MagicMock()
    registry.update_status = AsyncMock()
    registry.unregister = AsyncMock()
    terminator = MagicMock()
    terminator.terminate = AsyncMock(return_value=True)
    config = WatchdogConfig(process_timeout=1.0, extra_buffer=0.0, max_hang_time=2.0)
    now = 10.0
    watchdog = ProcessWatchdog(
        registry,
        signal_dispatcher=None,
        config=config,
        termination_strategy=terminator,
        clock=lambda: now,
    )

    process = SimpleNamespace(returncode=None)
    proc_config = ProcessConfig(command=["x"], name="proc")
    processes = {
        123: {
            "process": process,
            "config": proc_config,
            "started_at": 0.0,
            "status": "running",
        }
    }
    watchdog._last_activity[123] = 0.0

    result = await watchdog.scan_once(processes)

    assert result["hung"] == [123]
    assert result["killed"] == [123]
    registry.update_status.assert_called_once_with(123, "stopped")
    registry.unregister.assert_called_once_with(123)


@pytest.mark.asyncio
async def test_scan_once_removes_finished_process():
    registry = MagicMock()
    registry.unregister = AsyncMock()
    watchdog = ProcessWatchdog(
        registry,
        signal_dispatcher=None,
        config=WatchdogConfig(),
        termination_strategy=MagicMock(),
        clock=lambda: 10.0,
    )

    process = SimpleNamespace(returncode=0)
    proc_config = ProcessConfig(command=["x"], name="proc")
    processes = {
        123: {
            "process": process,
            "config": proc_config,
            "started_at": 0.0,
            "status": "done",
        }
    }

    result = await watchdog.scan_once(processes)

    assert result["removed"] == [123]
    registry.unregister.assert_called_once_with(123)


@pytest.mark.asyncio
async def test_get_stats_with_metrics_sampler_error():
    registry = MagicMock()
    registry.snapshot = AsyncMock(return_value={})
    watchdog = ProcessWatchdog(
        registry,
        signal_dispatcher=None,
        metrics_sampler=lambda: 1 / 0,
    )

    stats = await watchdog.get_stats()

    assert stats["total_processes"] == 0
