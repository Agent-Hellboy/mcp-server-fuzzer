#!/usr/bin/env python3
"""
ProcessWatchdog tests (registry-backed).
"""

import asyncio
import logging

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

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


# ---------------------------------------------------------------------------
# Extended coverage tests (merged from test_watchdog_extended.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_registry():
    """Create a mock ProcessRegistry."""
    registry = MagicMock()
    registry.snapshot = AsyncMock(return_value={})
    registry.update_status = AsyncMock()
    registry.unregister = AsyncMock()
    return registry


@pytest.fixture
def mock_dispatcher():
    """Create a mock SignalDispatcher."""
    dispatcher = MagicMock()
    dispatcher.send = AsyncMock()
    return dispatcher


@pytest.fixture
def watchdog_config():
    """Create a WatchdogConfig for testing."""
    return WatchdogConfig(
        check_interval=0.1,
        process_timeout=1.0,
        extra_buffer=0.5,
        max_hang_time=5.0,
        auto_kill=True,
    )


class TestWaitForProcessExit:
    """Test wait_for_process_exit function."""

    @pytest.mark.asyncio
    async def test_sync_wait_result(self):
        """Test with synchronous wait result."""
        process = MagicMock()
        process.wait = MagicMock(return_value=0)
        result = await wait_for_process_exit(process)
        assert result == 0

    @pytest.mark.asyncio
    async def test_async_wait_result(self):
        """Test with async wait result."""
        async def async_wait():
            return 0
        process = MagicMock()
        process.wait = MagicMock(side_effect=async_wait)
        result = await wait_for_process_exit(process)
        assert result == 0

    @pytest.mark.asyncio
    async def test_async_wait_with_timeout(self):
        """Test async wait with timeout that completes in time."""
        async def async_wait():
            return 0
        process = MagicMock()
        process.wait = MagicMock(side_effect=async_wait)
        result = await wait_for_process_exit(process, timeout=5.0)
        assert result == 0


class TestNormalizeActivity:
    """Test _normalize_activity function."""

    @pytest.mark.asyncio
    async def test_no_callback_returns_last_activity(self):
        """Test that None callback returns last activity."""
        result = await _normalize_activity(None, 100.0, 200.0, MagicMock())
        assert result == 100.0

    @pytest.mark.asyncio
    async def test_callback_returns_float(self):
        """Test callback returning a float timestamp."""
        callback = MagicMock(return_value=150.0)
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 150.0

    @pytest.mark.asyncio
    async def test_callback_returns_true(self):
        """Test callback returning True updates to current time."""
        callback = MagicMock(return_value=True)
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 200.0

    @pytest.mark.asyncio
    async def test_callback_returns_false(self):
        """Test callback returning False retains last activity."""
        callback = MagicMock(return_value=False)
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 100.0

    @pytest.mark.asyncio
    async def test_callback_raises_exception(self):
        """Test callback raising exception falls back to last activity."""
        callback = MagicMock(side_effect=Exception("fail"))
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 100.0

    @pytest.mark.asyncio
    async def test_callback_returns_invalid_timestamp(self):
        """Test callback returning invalid timestamp falls back."""
        # Timestamp too far in the future
        callback = MagicMock(return_value=999999.0)
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 100.0

    @pytest.mark.asyncio
    async def test_callback_returns_negative_timestamp(self):
        """Test callback returning negative timestamp falls back."""
        callback = MagicMock(return_value=-1.0)
        result = await _normalize_activity(callback, 100.0, 200.0, MagicMock())
        assert result == 100.0

    @pytest.mark.asyncio
    async def test_async_callback(self):
        """Test async callback."""
        async def async_callback():
            return 150.0
        result = await _normalize_activity(async_callback, 100.0, 200.0, MagicMock())
        assert result == 150.0


class TestSignalTerminationStrategy:
    """Test SignalTerminationStrategy."""

    @pytest.mark.asyncio
    async def test_graceful_termination_success(self, mock_dispatcher):
        """Test successful graceful termination."""
        logger = MagicMock()

        async def mock_wait(process, timeout):
            return 0

        strategy = SignalTerminationStrategy(
            dispatcher=mock_dispatcher,
            logger=logger,
            graceful_timeout=1.0,
            force_timeout=1.0,
            wait_fn=mock_wait,
        )

        process = MagicMock()
        process.returncode = None
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        result = await strategy.terminate(123, process_info, 10.0)
        assert result is True
        mock_dispatcher.send.assert_called_with("timeout", 123, process_info)

    @pytest.mark.asyncio
    async def test_force_termination_after_graceful_timeout(self, mock_dispatcher):
        """Test force termination after graceful timeout."""
        logger = MagicMock()
        call_count = 0

        async def mock_wait(process, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # First call (graceful) times out
                raise asyncio.TimeoutError()
            return 0  # Second call (force) succeeds

        strategy = SignalTerminationStrategy(
            dispatcher=mock_dispatcher,
            logger=logger,
            graceful_timeout=0.1,
            force_timeout=0.1,
            wait_fn=mock_wait,
        )

        process = MagicMock()
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        result = await strategy.terminate(123, process_info, 10.0)
        assert result is True
        assert mock_dispatcher.send.call_count == 2


class TestBestEffortTerminationStrategy:
    """Test BestEffortTerminationStrategy."""

    @pytest.mark.asyncio
    async def test_termination_on_unix(self):
        """Test termination on Unix systems."""
        logger = MagicMock()

        async def mock_wait(process, timeout):
            return 0

        strategy = BestEffortTerminationStrategy(logger=logger, wait_fn=mock_wait)

        process = MagicMock()
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        with patch("sys.platform", "linux"):
            with patch("os.getpgid", return_value=123):
                with patch("os.killpg"):
                    result = await strategy.terminate(123, process_info, 10.0)
                    assert result is True

    @pytest.mark.asyncio
    async def test_termination_on_windows(self):
        """Test termination on Windows systems."""
        logger = MagicMock()
        wait_fn = AsyncMock(return_value=None)
        strategy = BestEffortTerminationStrategy(logger=logger, wait_fn=wait_fn)

        process = MagicMock()
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        with patch("sys.platform", "win32"):
            result = await strategy.terminate(123, process_info, 10.0)

        process.terminate.assert_called_once()
        process.kill.assert_not_called()
        assert result is True

    @pytest.mark.asyncio
    async def test_fallback_on_oserror(self):
        """Test fallback to process termination when getpgid fails."""
        logger = MagicMock()
        wait_fn = AsyncMock(return_value=None)
        strategy = BestEffortTerminationStrategy(logger=logger, wait_fn=wait_fn)

        process = MagicMock()
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        with patch("sys.platform", "linux"):
            with patch("os.getpgid", side_effect=OSError("no pgid")):
                result = await strategy.terminate(123, process_info, 10.0)

        process.terminate.assert_called_once()
        process.kill.assert_not_called()
        assert result is True

    @pytest.mark.asyncio
    async def test_force_kill_after_timeout(self):
        """Test force kill path after graceful timeout."""
        logger = MagicMock()
        wait_fn = AsyncMock(
            side_effect=[asyncio.TimeoutError(), None]
        )
        strategy = BestEffortTerminationStrategy(logger=logger, wait_fn=wait_fn)

        process = MagicMock()
        config = ProcessConfig(command=["test"], name="test_proc")
        process_info = {"process": process, "config": config}

        with patch("sys.platform", "linux"):
            with patch("os.getpgid", return_value=123):
                with patch("os.killpg") as mock_killpg:
                    result = await strategy.terminate(123, process_info, 10.0)

        assert mock_killpg.call_count == 2
        assert result is True


class TestProcessWatchdog:
    """Test ProcessWatchdog class."""

    @pytest.mark.asyncio
    async def test_start_stop(self, mock_registry, mock_dispatcher, watchdog_config):
        """Test starting and stopping the watchdog."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
        )

        await watchdog.start()
        assert watchdog._task is not None

        await watchdog.stop()
        assert watchdog._task is None

    @pytest.mark.asyncio
    async def test_start_already_running(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test starting when already running is a no-op."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
        )

        await watchdog.start()
        first_task = watchdog._task

        await watchdog.start()  # Should not create new task
        assert watchdog._task is first_task

        await watchdog.stop()

    @pytest.mark.asyncio
    async def test_update_activity(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test updating activity for a process."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=lambda: 1000.0,
        )

        await watchdog.update_activity(123)
        assert watchdog._last_activity[123] == 1000.0

    @pytest.mark.asyncio
    async def test_scan_once_removes_finished_processes(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test scan_once removes finished processes."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=lambda: 1000.0,
        )

        process = MagicMock()
        process.returncode = 0  # Process has finished
        config = ProcessConfig(command=["test"], name="test_proc")

        processes = {
            123: {"process": process, "config": config, "started_at": 900.0}
        }

        result = await watchdog.scan_once(processes)
        assert 123 in result["removed"]
        mock_registry.unregister.assert_called_with(123)

    @pytest.mark.asyncio
    async def test_scan_once_detects_hung_processes(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test scan_once detects hung processes."""
        call_time = [1000.0]
        def mock_clock():
            return call_time[0]

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=mock_clock,
        )

        process = MagicMock()
        process.returncode = None  # Still running
        config = ProcessConfig(command=["test"], name="test_proc")

        # Set up process with old activity timestamp
        watchdog._last_activity[123] = 900.0  # 100 seconds ago

        processes = {
            123: {"process": process, "config": config, "started_at": 900.0}
        }

        # Mock the terminator to succeed
        watchdog._terminator.terminate = AsyncMock(return_value=True)

        result = await watchdog.scan_once(processes)
        assert 123 in result["hung"]
        assert 123 in result["killed"]
        mock_registry.update_status.assert_awaited_once_with(123, "stopped")

    @pytest.mark.asyncio
    async def test_scan_once_cleans_up_missing_pids(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test scan_once cleans up metadata for missing PIDs."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=lambda: 1000.0,
        )

        # Pre-populate activity for a PID that no longer exists
        watchdog._last_activity[999] = 900.0

        processes = {}  # Empty - no processes

        result = await watchdog.scan_once(processes)
        assert 999 not in watchdog._last_activity

    @pytest.mark.asyncio
    async def test_get_stats(self, mock_registry, mock_dispatcher, watchdog_config):
        """Test get_stats returns watchdog statistics."""
        process = MagicMock()
        process.returncode = None
        config = ProcessConfig(command=["test"], name="test_proc")

        mock_registry.snapshot = AsyncMock(
            return_value={123: {"process": process, "config": config}}
        )

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
        )

        stats = await watchdog.get_stats()
        assert stats["total_processes"] == 1
        assert stats["running_processes"] == 1
        assert stats["finished_processes"] == 0
        assert stats["watchdog_active"] is False

    @pytest.mark.asyncio
    async def test_get_stats_with_metrics_sampler(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test get_stats includes metrics from sampler."""
        mock_registry.snapshot = AsyncMock(return_value={})

        def metrics_sampler():
            return {"cpu": 50, "memory": 1024}

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            metrics_sampler=metrics_sampler,
        )

        stats = await watchdog.get_stats()
        assert "system_metrics" in stats
        assert stats["system_metrics"]["cpu"] == 50

    @pytest.mark.asyncio
    async def test_get_stats_metrics_sampler_error_is_swallowed(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """A raising metrics sampler is logged and omitted, not propagated."""
        mock_registry.snapshot = AsyncMock(return_value={})

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            metrics_sampler=lambda: 1 / 0,
        )

        stats = await watchdog.get_stats()
        assert "system_metrics" not in stats

    @pytest.mark.asyncio
    async def test_context_manager(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test watchdog as async context manager."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
        )

        async with watchdog:
            assert watchdog._task is not None

        assert watchdog._task is None

    @pytest.mark.asyncio
    async def test_on_hang_callback(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test on_hang callback is called for hung processes."""
        hang_callback = MagicMock()

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=lambda: 1000.0,
            on_hang=hang_callback,
        )

        process = MagicMock()
        process.returncode = None
        config = ProcessConfig(command=["test"], name="test_proc")

        watchdog._last_activity[123] = 900.0
        watchdog._terminator.terminate = AsyncMock(return_value=True)

        processes = {
            123: {"process": process, "config": config, "started_at": 900.0}
        }

        await watchdog.scan_once(processes)
        hang_callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_on_hang_callback_exception_handled(
        self, mock_registry, mock_dispatcher, watchdog_config
    ):
        """Test on_hang callback exception is handled gracefully."""
        def failing_callback(pid, info, duration):
            raise Exception("callback failed")

        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=mock_dispatcher,
            config=watchdog_config,
            clock=lambda: 1000.0,
            on_hang=failing_callback,
        )

        process = MagicMock()
        process.returncode = None
        config = ProcessConfig(command=["test"], name="test_proc")

        watchdog._last_activity[123] = 900.0
        watchdog._terminator.terminate = AsyncMock(return_value=True)

        processes = {
            123: {"process": process, "config": config, "started_at": 900.0}
        }

        # Should not raise despite callback failure
        result = await watchdog.scan_once(processes)
        assert 123 in result["hung"]

    @pytest.mark.asyncio
    async def test_fallback_to_best_effort_strategy(
        self, mock_registry, watchdog_config
    ):
        """Test fallback to BestEffortTerminationStrategy when no dispatcher."""
        watchdog = ProcessWatchdog(
            registry=mock_registry,
            signal_dispatcher=None,  # No dispatcher
            config=watchdog_config,
        )

        assert isinstance(watchdog._terminator, BestEffortTerminationStrategy)
