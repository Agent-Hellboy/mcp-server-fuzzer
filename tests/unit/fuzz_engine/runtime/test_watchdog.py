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
from mcp_fuzzer.fuzz_engine.runtime.watchdog import (
    BestEffortTerminationStrategy,
    SignalTerminationStrategy,
    _normalize_activity,
    wait_for_process_exit,
)
from mcp_fuzzer.exceptions import ProcessStopError


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


class DummyProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self):
        return None


class DummyTerminator:
    def __init__(self):
        self.calls = []

    async def terminate(self, pid, process_info, hang_duration):
        self.calls.append((pid, hang_duration))
        return True


@pytest.mark.asyncio
async def test_normalize_activity_paths():
    now = 10.0
    last = 5.0
    logger = logging.getLogger("test")

    assert await _normalize_activity(lambda: True, last, now, logger) == now
    assert await _normalize_activity(lambda: False, last, now, logger) == last
    assert await _normalize_activity(lambda: 7.0, last, now, logger) == 7.0
    assert await _normalize_activity(lambda: -1.0, last, now, logger) == last

    def _raise():
        raise RuntimeError("boom")

    assert await _normalize_activity(_raise, last, now, logger) == last
    assert await _normalize_activity(lambda: object(), last, now, logger) == last


@pytest.mark.asyncio
async def test_scan_once_removes_and_kills(monkeypatch):
    registry = ProcessRegistry()
    terminator = DummyTerminator()
    config = WatchdogConfig(process_timeout=1.0, extra_buffer=0.0, auto_kill=True)
    watchdog = ProcessWatchdog(
        registry, None, config=config, termination_strategy=terminator
    )

    done_proc = DummyProcess(returncode=0)
    hung_proc = DummyProcess(returncode=None)

    done_config = ProcessConfig(command=["echo"], name="done")
    hung_config = ProcessConfig(command=["sleep"], name="hung")

    await registry.register(1, done_proc, done_config, started_at=0.0)
    await registry.register(2, hung_proc, hung_config, started_at=0.0)

    watchdog._last_activity[2] = 0.0
    monkeypatch.setattr(watchdog, "_clock", lambda: 10.0)

    result = await watchdog.scan_once(await registry.snapshot())
    assert 1 in result["removed"]
    assert 2 in result["killed"]
    assert terminator.calls


@pytest.mark.asyncio
async def test_get_stats_includes_metrics(monkeypatch):
    registry = ProcessRegistry()
    watchdog = ProcessWatchdog(
        registry,
        None,
        metrics_sampler=lambda: {"cpu": 1},
    )
    stats = await watchdog.get_stats()
    assert stats["system_metrics"] == {"cpu": 1}


@pytest.mark.asyncio
async def test_wait_for_process_exit_sync():
    proc = DummyProcess(returncode=0)
    assert await wait_for_process_exit(proc, timeout=0.1) is None


@pytest.mark.asyncio
async def test_signal_termination_strategy_escalates(monkeypatch):
    events = []

    class DummyDispatcher:
        async def send(self, signal_type, pid, process_info):
            events.append(signal_type)

    calls = {"count": 0}

    async def _wait_fn(_process, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise asyncio.TimeoutError()
        return None

    strategy = SignalTerminationStrategy(
        DummyDispatcher(), logging.getLogger("test"), wait_fn=_wait_fn
    )
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}
    result = await strategy.terminate(1, record, 10.0)
    assert result is True
    assert events == ["timeout", "force"]


@pytest.mark.asyncio
async def test_signal_termination_strategy_returns_false():
    class DummyDispatcher:
        async def send(self, signal_type, pid, process_info):
            return None

    async def _wait_fn(_process, timeout=None):
        raise asyncio.TimeoutError()

    strategy = SignalTerminationStrategy(
        DummyDispatcher(), logging.getLogger("test"), wait_fn=_wait_fn
    )
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}
    result = await strategy.terminate(1, record, 10.0)
    assert result is False


@pytest.mark.asyncio
async def test_best_effort_termination_uses_fallback(monkeypatch):
    strategy = BestEffortTerminationStrategy(logging.getLogger("test"))
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.runtime.watchdog.os.getpgid",
        lambda pid: 1,
    )
    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.runtime.watchdog.os.killpg",
        lambda *args, **kwargs: None,
    )
    calls = {"count": 0}

    async def _await_exit(*_args, **_kwargs):
        calls["count"] += 1
        return calls["count"] == 2

    monkeypatch.setattr(strategy, "_await_exit", _await_exit)

    result = await strategy.terminate(1, record, 5.0)
    assert result is True


@pytest.mark.asyncio
async def test_best_effort_windows_termination(monkeypatch):
    strategy = BestEffortTerminationStrategy(logging.getLogger("test"))
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}

    async def _await_exit(*_args, **_kwargs):
        return True

    monkeypatch.setattr(strategy, "_await_exit", _await_exit)
    monkeypatch.setattr("mcp_fuzzer.fuzz_engine.runtime.watchdog.sys.platform", "win32")

    result = await strategy.terminate(1, record, 5.0)
    assert result is True


@pytest.mark.asyncio
async def test_best_effort_termination_raises(monkeypatch):
    strategy = BestEffortTerminationStrategy(logging.getLogger("test"))
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}

    def _raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.runtime.watchdog.os.getpgid",
        _raise_error,
    )

    with pytest.raises(ProcessStopError):
        await strategy.terminate(1, record, 5.0)


@pytest.mark.asyncio
async def test_best_effort_windows_force_kill(monkeypatch):
    strategy = BestEffortTerminationStrategy(logging.getLogger("test"))
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}

    calls = {"count": 0}

    async def _await_exit(*_args, **_kwargs):
        calls["count"] += 1
        return calls["count"] == 2

    monkeypatch.setattr(strategy, "_await_exit", _await_exit)
    monkeypatch.setattr("mcp_fuzzer.fuzz_engine.runtime.watchdog.sys.platform", "win32")

    result = await strategy.terminate(1, record, 5.0)
    assert result is True
    assert proc.killed is True


@pytest.mark.asyncio
async def test_best_effort_oserror_force_kill(monkeypatch):
    strategy = BestEffortTerminationStrategy(logging.getLogger("test"))
    proc = DummyProcess(returncode=None)
    config = ProcessConfig(command=["echo"], name="p")
    record = {"process": proc, "config": config, "started_at": 0.0, "status": "running"}

    async def _await_exit(*_args, **_kwargs):
        return False

    monkeypatch.setattr(strategy, "_await_exit", _await_exit)

    def _raise_oserror(*_args, **_kwargs):
        raise OSError("boom")

    monkeypatch.setattr(
        "mcp_fuzzer.fuzz_engine.runtime.watchdog.os.getpgid",
        _raise_oserror,
    )

    result = await strategy.terminate(1, record, 5.0)
    assert result is False
