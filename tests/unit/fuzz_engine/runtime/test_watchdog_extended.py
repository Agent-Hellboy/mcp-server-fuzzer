"""Extended tests for watchdog.py to improve coverage."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from mcp_fuzzer.fuzz_engine.runtime.watchdog import (
    ProcessWatchdog,
    SignalTerminationStrategy,
    BestEffortTerminationStrategy,
    _normalize_activity,
    wait_for_process_exit,
)
from mcp_fuzzer.fuzz_engine.runtime.config import WatchdogConfig, ProcessConfig


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
