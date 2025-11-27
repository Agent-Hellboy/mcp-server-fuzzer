#!/usr/bin/env python3
"""
ProcessWatchdog tests (registry-backed).
"""

import asyncio
import logging

import pytest
from unittest.mock import AsyncMock

from mcp_fuzzer.fuzz_engine.runtime import (
    ProcessConfig,
    ProcessRegistry,
    ProcessWatchdog,
    SignalDispatcher,
    WatchdogConfig,
)


class ClockStub:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, delta: float) -> None:
        self.now += delta


class FakeTermination:
    def __init__(self) -> None:
        self.calls: list[int] = []

    async def terminate(self, pid: int, process_info, hang_duration: float) -> bool:
        self.calls.append(pid)
        return True


@pytest.fixture
def logger():
    return logging.getLogger(__name__)


@pytest.fixture
def registry():
    return ProcessRegistry()


@pytest.fixture
def signal_dispatcher(registry, logger):
    return SignalDispatcher(registry, logger)


@pytest.mark.asyncio
async def test_start_stop(registry, signal_dispatcher, logger):
    watchdog = ProcessWatchdog(registry, signal_dispatcher, logger=logger)
    await watchdog.start()
    stats = await watchdog.get_stats()
    assert stats["watchdog_active"] is True
    await watchdog.stop()
    stats = await watchdog.get_stats()
    assert stats["watchdog_active"] is False


@pytest.mark.asyncio
async def test_scan_once_respects_registry(registry, signal_dispatcher, logger):
    config = WatchdogConfig(process_timeout=1.0, extra_buffer=0.0)
    watchdog = ProcessWatchdog(registry, signal_dispatcher, config, logger=logger)

    mock_process = AsyncMock()
    mock_process.pid = 42
    mock_process.returncode = None
    await registry.register(
        42, mock_process, ProcessConfig(command=["echo"], name="echo")
    )
    result = await watchdog.scan_once(await registry.snapshot())
    assert result["hung"] == []
    stats = await watchdog.get_stats()
    assert stats["total_processes"] == 1

    # Mark finished and ensure removal occurs
    mock_process.returncode = 0
    result = await watchdog.scan_once(await registry.snapshot())
    assert 42 in result["removed"]


@pytest.mark.asyncio
async def test_hang_detection_uses_clock(registry, logger):
    clock = ClockStub()
    fake_terminator = FakeTermination()
    config = WatchdogConfig(
        check_interval=0.1, process_timeout=1.0, extra_buffer=0.0, auto_kill=True
    )
    watchdog = ProcessWatchdog(
        registry,
        signal_dispatcher=None,
        config=config,
        termination_strategy=fake_terminator,
        clock=clock,
        logger=logger,
    )

    mock_process = AsyncMock()
    mock_process.pid = 99
    mock_process.returncode = None
    await registry.register(
        99,
        mock_process,
        ProcessConfig(command=["sleep", "10"], name="slow"),
        started_at=clock.now,
    )

    await watchdog.update_activity(99)
    await watchdog.scan_once(await registry.snapshot())
    assert fake_terminator.calls == []

    clock.advance(2.0)
    await watchdog.scan_once(await registry.snapshot())
    assert fake_terminator.calls == [99]


@pytest.mark.asyncio
async def test_activity_callback_boolean(registry, logger):
    clock = ClockStub()
    fake_terminator = FakeTermination()
    watchdog = ProcessWatchdog(
        registry,
        signal_dispatcher=None,
        config=WatchdogConfig(process_timeout=0.5, extra_buffer=0.0, auto_kill=True),
        termination_strategy=fake_terminator,
        clock=clock,
        logger=logger,
    )

    mock_process = AsyncMock()
    mock_process.pid = 7
    mock_process.returncode = None
    cfg = ProcessConfig(command=["echo"], name="echo", activity_callback=lambda: True)
    await registry.register(7, mock_process, cfg, started_at=clock.now)

    # Callback returns True -> treated as recent activity; no hang
    clock.advance(1.0)
    await watchdog.scan_once(await registry.snapshot())
    assert fake_terminator.calls == []

    # Callback returns False -> stick with stale activity and kill on next scan
    cfg.activity_callback = lambda: False
    clock.advance(1.0)
    await watchdog.scan_once(await registry.snapshot())
    assert fake_terminator.calls == [7]
