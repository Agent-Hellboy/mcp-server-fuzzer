import asyncio
import os
import time
from unittest.mock import patch, MagicMock, AsyncMock, call
import pytest

# Import the classes to test
from mcp_fuzzer.fuzz_engine.runtime.watchdog import (
    ProcessWatchdog,
    WatchdogConfig,
)
import signal as _signal
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessConfig
import signal


class TestProcessWatchdog:
    def setUp(self):
        """Set up test fixtures."""
        self.config = WatchdogConfig(
            check_interval=0.1,
            process_timeout=1.0,
            extra_buffer=0.5,
            max_hang_time=2.0,
            auto_kill=True,
        )
        self.watchdog = ProcessWatchdog(self.config)
        self.mock_process = MagicMock()
        self.mock_process.pid = 12345
        self.mock_process.returncode = None

    def test_init(self):
        """Test initialization of the watchdog."""
        watchdog = ProcessWatchdog()
        assert watchdog.config is not None
        assert watchdog._processes == {}
        assert watchdog._watchdog_task is None

        # Test with custom config
        config = WatchdogConfig(check_interval=2.0)
        watchdog = ProcessWatchdog(config)
        assert watchdog.config.check_interval == 2.0

    def test_start_watchdog(self):
        """Test starting the watchdog."""
        self.setUp()
        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.create_task = MagicMock()
            self.watchdog.start()
            assert self.watchdog._watchdog_task is not None
            mock_loop.return_value.create_task.assert_called_once()

    def test_start_watchdog_no_loop(self):
        """Test starting the watchdog without a running loop."""
        self.setUp()
        with patch("asyncio.get_running_loop", side_effect=RuntimeError):
            self.watchdog.start()
            assert self.watchdog._watchdog_task is None

    def test_stop_watchdog_active(self):
        """Test stopping an active watchdog."""
        self.setUp()
        # Create a mock task
        mock_task = MagicMock()
        mock_task.done.return_value = False

        # Set it directly to simulate an active task
        self.watchdog._watchdog_task = mock_task

        # Stop the watchdog
        self.watchdog.stop()

        # Verify the stop was handled correctly
        assert self.watchdog._stop_event.is_set()
        mock_task.cancel.assert_called_once()
        assert self.watchdog._watchdog_task is None

    def test_stop_watchdog_inactive(self):
        """Test stopping an inactive watchdog."""
        self.setUp()
        self.watchdog.stop()
        # No assertion needed, just ensure no crash

    def test_register_process(self):
        """Test registering a process."""
        self.setUp()
        mock_process = MagicMock()
        mock_process.pid = 12345

        self.watchdog.register_process(12345, mock_process, None, "test")

        # Assert process was registered
        assert 12345 in self.watchdog._processes
        assert self.watchdog._processes[12345]["name"] == "test"
        assert self.watchdog._processes[12345]["process"] == mock_process

    def test_unregister_process(self):
        """Test unregistering a process."""
        self.setUp()
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Register process
        self.watchdog.register_process(12345, mock_process, None, "test")

        # Unregister process
        self.watchdog.unregister_process(12345)

        # Assert process was unregistered
        assert 12345 not in self.watchdog._processes

    def test_update_activity(self):
        """Test updating activity for a process."""
        self.setUp()
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Register process
        self.watchdog.register_process(12345, mock_process, None, "test")

        # Get initial activity time
        initial_time = self.watchdog._processes[12345]["last_activity"]

        # Wait a bit
        time.sleep(0.1)

        # Update activity
        self.watchdog.update_activity(12345)

        # Assert activity time was updated
        assert self.watchdog._processes[12345]["last_activity"] > initial_time

    def test_get_stats(self):
        """Test getting statistics."""
        self.setUp()
        # Register two processes
        mock_process1 = MagicMock()
        mock_process1.pid = 1111
        mock_process1.returncode = None
        mock_process2 = MagicMock()
        mock_process2.pid = 2222
        mock_process2.returncode = 0  # Finished

        self.watchdog.register_process(1111, mock_process1, None, "running")
        self.watchdog.register_process(2222, mock_process2, None, "finished")

        # Get stats
        stats = self.watchdog.get_stats()

        # Assert stats are correct - check for the keys that actually exist
        assert stats["total_processes"] == 2
        assert stats["running_processes"] == 1
        assert stats["finished_processes"] == 1
        assert "watchdog_active" in stats
