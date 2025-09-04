import asyncio
import os
import signal as _signal
import signal
import time

import pytest
from unittest.mock import patch, MagicMock, AsyncMock, call

# Import the classes to test
from mcp_fuzzer.fuzz_engine.runtime.watchdog import (
    ProcessWatchdog,
    WatchdogConfig,
)


class TestProcessWatchdog:
    @pytest.fixture(autouse=True)
    def setup_method(self):
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

    @pytest.mark.asyncio
    async def test_start_watchdog(self):
        """Test starting the watchdog."""
        with patch("asyncio.create_task") as mock_create_task:
            await self.watchdog.start()
            assert mock_create_task.called
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_watchdog_no_loop(self):
        """Test starting the watchdog without a running loop."""
        # Since the start method is now async, we need to simulate a failure inside it
        with patch("asyncio.create_task", side_effect=RuntimeError("Test exception")):
            try:
                await self.watchdog.start()
            except RuntimeError:
                # Expected exception
                pass
            # The task should not be created due to the exception
            assert self.watchdog._watchdog_task is None

    @pytest.mark.asyncio
    async def test_stop_watchdog_active(self):
        """Test stopping an active watchdog."""
        # Create a mock task
        mock_task = MagicMock()
        mock_task.done.return_value = False

        # Set it directly to simulate an active task
        self.watchdog._watchdog_task = mock_task

        # Stop the watchdog
        await self.watchdog.stop()

        # Verify the stop was handled correctly
        assert self.watchdog._stop_event.is_set()
        mock_task.cancel.assert_called_once()
        assert self.watchdog._watchdog_task is None

    @pytest.mark.asyncio
    async def test_stop_watchdog_inactive(self):
        """Test stopping an inactive watchdog."""
        await self.watchdog.stop()
        # No assertion needed, just ensure no crash

    @pytest.mark.asyncio
    async def test_register_process(self):
        """Test registering a process."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Mock start method to avoid creating an actual task
        with patch.object(self.watchdog, "start", AsyncMock()):
            await self.watchdog.register_process(12345, mock_process, None, "test")

            # Assert process was registered
            assert 12345 in self.watchdog._processes
            assert self.watchdog._processes[12345]["name"] == "test"
            assert self.watchdog._processes[12345]["process"] == mock_process

    @pytest.mark.asyncio
    async def test_unregister_process(self):
        """Test unregistering a process."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Register process
        with patch.object(self.watchdog, "start", AsyncMock()):
            await self.watchdog.register_process(12345, mock_process, None, "test")

            # Unregister process
            await self.watchdog.unregister_process(12345)

            # Assert process was unregistered
            assert 12345 not in self.watchdog._processes

    @pytest.mark.asyncio
    async def test_update_activity(self):
        """Test updating activity for a process."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        # Register process
        with patch.object(self.watchdog, "start", AsyncMock()):
            await self.watchdog.register_process(12345, mock_process, None, "test")

            # Get initial activity time
            initial_time = self.watchdog._processes[12345]["last_activity"]

            # Wait a bit
            await asyncio.sleep(0.1)

            # Update activity
            await self.watchdog.update_activity(12345)

            # Assert activity time was updated
            assert self.watchdog._processes[12345]["last_activity"] > initial_time

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting statistics."""
        # Register two processes
        mock_process1 = MagicMock()
        mock_process1.pid = 1111
        mock_process1.returncode = None
        mock_process2 = MagicMock()
        mock_process2.pid = 2222
        mock_process2.returncode = 0  # Finished

        # Register processes
        with patch.object(self.watchdog, "start", AsyncMock()):
            await self.watchdog.register_process(1111, mock_process1, None, "running")
            await self.watchdog.register_process(2222, mock_process2, None, "finished")

            # Get stats
            stats = await self.watchdog.get_stats()

            # Assert stats are correct - check for the keys that actually exist
            assert stats["total_processes"] == 2
            assert stats["running_processes"] == 1
            assert stats["finished_processes"] == 1
            assert "watchdog_active" in stats
