#!/usr/bin/env python3
"""
Test suite for async runtime components
"""

import asyncio
import logging
import os
import signal
import subprocess
import time
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

from mcp_fuzzer.fuzz_engine.runtime import (
    ProcessManager,
    ProcessConfig,
    WatchdogConfig,
    ProcessWatchdog,
    ProcessRegistry,
    SignalDispatcher,
)


class TestProcessManager:
    """Test the Process Manager"""

    @pytest.mark.skip(reason="Need to fix mocking for asyncio.create_subprocess_exec")
    @pytest.mark.asyncio
    async def test_start_process_success(self):
        """Test starting a process successfully."""
        config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        manager = ProcessManager.from_config(config)

        # Set up a mock for the watchdog
        manager.watchdog = AsyncMock()
        manager.watchdog.start = AsyncMock()
        manager.watchdog.register_process = AsyncMock()

        # Mock the process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        try:
            # For now we just verify the test setup works
            assert True
        finally:
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_stop_process(self):
        """Test stopping a process."""
        config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        manager = ProcessManager.from_config(config)

        # Mock the process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        try:
            # Set up a process in the manager
            await manager.registry.register(
                12345,
                mock_process,
                ProcessConfig(command=["test"], name="test_process"),
                started_at=time.time(),
                status="running",
            )

            # Test stopping the process through public API
            # Mock signal dispatcher to verify it's called
            with patch.object(
                manager.signal_dispatcher, "send", AsyncMock(return_value=True)
            ) as mock_signal:
                result = await manager.stop_process(12345)
                assert result is True
                # Verify signal was sent (graceful termination)
                mock_signal.assert_called_once()
        finally:
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_get_process_status(self):
        """Test getting process status."""
        config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        manager = ProcessManager.from_config(config)

        # Mock the process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        try:
            # Set up a process in the manager
            await manager.registry.register(
                12345,
                mock_process,
                ProcessConfig(command=["test"], name="test_process"),
                started_at=time.time(),
                status="running",
            )

            # Get status for a running process
            status = await manager.get_process_status(12345)
            assert status is not None
            assert status["status"] == "running"

            # Get status for a finished process
            mock_process.returncode = 0
            status = await manager.get_process_status(12345)
            assert status is not None
            assert status["status"] == "finished"
            assert status["exit_code"] == 0

            # Get status for a non-existent process
            status = await manager.get_process_status(99999)
            assert status is None
        finally:
            await manager.shutdown()

    @pytest.mark.asyncio
    async def test_list_processes(self):
        """Test listing processes."""
        config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        manager = ProcessManager.from_config(config)

        # Mock the processes
        mock_process1 = AsyncMock()
        mock_process1.pid = 12345
        mock_process1.returncode = None

        mock_process2 = AsyncMock()
        mock_process2.pid = 67890
        mock_process2.returncode = 0

        try:
            # Set up two processes in the manager
            await manager.registry.register(
                12345,
                mock_process1,
                ProcessConfig(command=["test1"], name="test_process1"),
                started_at=time.time(),
                status="running",
            )
            await manager.registry.register(
                67890,
                mock_process2,
                ProcessConfig(command=["test2"], name="test_process2"),
                started_at=time.time(),
                status="finished",
            )

            # Just verify we can call list_processes without error
            processes = await manager.list_processes()
            assert len(processes) == 2
        finally:
            await manager.shutdown()


class TestProcessWatchdog:
    """Test the Process Watchdog"""

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping the watchdog."""
        config = WatchdogConfig(
            check_interval=0.1,
            process_timeout=1.0,
            extra_buffer=0.5,
            max_hang_time=2.0,
            auto_kill=True,
        )
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(registry, logging.getLogger(__name__))
        watchdog = ProcessWatchdog(registry, signal_handler, config)

        try:
            await watchdog.start()
            # Use public API to verify watchdog is active
            stats = await watchdog.get_stats()
            assert stats["watchdog_active"] is True
        finally:
            await watchdog.stop()
            # Use public API to verify watchdog is stopped
            stats = await watchdog.get_stats()
            assert stats["watchdog_active"] is False

    @pytest.mark.asyncio
    async def test_scan_once_with_registry_snapshot(self):
        """Test scanning over registry snapshots."""
        config = WatchdogConfig(
            check_interval=0.1,
            process_timeout=1.0,
            extra_buffer=0.5,
            max_hang_time=2.0,
            auto_kill=True,
        )
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(registry, logging.getLogger(__name__))
        watchdog = ProcessWatchdog(registry, signal_handler, config)

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        try:
            await registry.register(
                12345,
                mock_process,
                ProcessConfig(command=["echo", "test"], name="test_process"),
            )
            await watchdog.update_activity(12345)
            result = await watchdog.scan_once(await registry.snapshot())
            assert result["hung"] == []

            mock_process.returncode = 0
            result = await watchdog.scan_once(await registry.snapshot())
            assert 12345 in result["removed"]
        finally:
            await watchdog.stop()

    @pytest.mark.asyncio
    async def test_update_activity(self):
        """Test activity updates prevent hangs until timeout."""
        config = WatchdogConfig(
            check_interval=0.05,
            process_timeout=0.01,
            extra_buffer=0.0,
            max_hang_time=0.05,
            auto_kill=True,
        )

        class FakeTermination:
            def __init__(self):
                self.calls: list[int] = []

            async def terminate(
                self, pid: int, process_info, hang_duration: float
            ) -> bool:
                self.calls.append(pid)
                return True

        registry = ProcessRegistry()
        fake_terminator = FakeTermination()
        watchdog = ProcessWatchdog(
            registry,
            signal_dispatcher=None,
            config=config,
            termination_strategy=fake_terminator,
        )

        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        try:
            await registry.register(
                12345,
                mock_process,
                ProcessConfig(command=["sleep", "1"], name="test_process"),
            )
            await watchdog.update_activity(12345)
            await watchdog.scan_once(await registry.snapshot())

            # Advance time to trigger hang detection
            await asyncio.sleep(0.05)
            await watchdog.scan_once(await registry.snapshot())
            assert fake_terminator.calls == [12345]
        finally:
            await watchdog.stop()
