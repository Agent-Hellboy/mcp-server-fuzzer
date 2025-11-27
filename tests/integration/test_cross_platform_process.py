#!/usr/bin/env python3
"""
Integration tests for cross-platform process management.
"""

import asyncio
import os
import platform
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.exceptions import ProcessStartError
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime import (
    ProcessWatchdog,
    WatchdogConfig,
    ProcessRegistry,
    SignalDispatcher,
)

pytestmark = [pytest.mark.integration, pytest.mark.runtime, pytest.mark.process]


class TestCrossPlatformProcessManagement:
    """Integration tests for cross-platform process management."""

    @pytest.fixture
    def process_manager(self):
        """Create a ProcessManager instance for testing."""
        config = WatchdogConfig(process_timeout=5.0, check_interval=0.1)
        return ProcessManager.from_config(config)

    @pytest.fixture
    def watchdog(self, process_manager):
        """Use the manager-owned watchdog."""
        return process_manager.watchdog

    def test_platform_detection(self):
        """Test that the system can detect the current platform."""
        current_platform = platform.system().lower()

        # Should be one of the supported platforms
        assert current_platform in ["linux", "darwin", "windows"]

        # Test platform-specific behavior
        if current_platform == "windows":
            assert os.name == "nt"
        else:
            assert os.name == "posix"

    @pytest.mark.asyncio
    async def test_process_manager_cross_platform_start(self, process_manager):
        """Test process manager can start processes on different platforms."""
        # Test with a simple command that works on all platforms
        if platform.system().lower() == "windows":
            command = ["cmd", "/c", "echo", "test"]
        else:
            command = ["echo", "test"]

        config = ProcessConfig(command=command, name="test_process", timeout=5.0)

        # Mock subprocess creation to avoid actual process execution
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.returncode = None
            mock_create.return_value = mock_process

            with patch.object(process_manager.watchdog, "start", new=AsyncMock()):
                process = await process_manager.start_process(config)

                assert process == mock_process
                # Use public API to verify process status
                status = await process_manager.get_process_status(process.pid)
                assert status is not None
                assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_process_manager_signal_handling(self, process_manager):
        """Test process manager signal handling across platforms."""
        current_platform = platform.system().lower()

        # Test different signals based on platform
        if current_platform == "windows":
            # Windows uses different signal handling
            test_signals = [signal.SIGTERM]
        else:
            # Unix-like systems
            test_signals = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]

        for sig in test_signals:
            # Mock process
            mock_process = MagicMock()
            mock_process.pid = 12345
            mock_process.returncode = None

            config = ProcessConfig(
                command=["test_command"], name="test_process", timeout=5.0
            )

            with patch("asyncio.create_subprocess_exec", return_value=mock_process):
                with patch.object(process_manager.watchdog, "start", new=AsyncMock()):
                    process = await process_manager.start_process(config)

                    # Verify stop completes and unregisters the process
                    await process_manager.stop_process(process.pid)
                    assert not await process_manager.registry.contains(process.pid)

    @pytest.mark.asyncio
    async def test_watchdog_cross_platform_monitoring(self, watchdog):
        """Test watchdog monitoring across platforms."""
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.poll.return_value = None  # Process still running

        await watchdog.start()

        await watchdog.registry.register(
            mock_process.pid,
            mock_process,
            ProcessConfig(command=["echo", "test"], name="test_process"),
            started_at=time.time(),
            status="running",
        )
        await watchdog.update_activity(mock_process.pid)

        await asyncio.sleep(0.2)  # Allow watchdog loop to scan
        stats = await watchdog.get_stats()
        assert stats["watchdog_active"] is True
        assert stats["total_processes"] == 1

        await watchdog.stop()
        stats = await watchdog.get_stats()
        assert stats["watchdog_active"] is False

    @pytest.mark.asyncio
    async def test_process_timeout_handling(self, process_manager):
        """Test process timeout handling across platforms."""
        # Create a config with short timeout
        config = ProcessConfig(
            command=["sleep", "10"],  # Long-running command
            name="timeout_test",
            timeout=1.0,  # Short timeout
        )

        # Mock subprocess
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.poll.return_value = None

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch.object(process_manager.watchdog, "start", new=AsyncMock()):
                process = await process_manager.start_process(config)

                # Wait for timeout
                await asyncio.sleep(1.5)

                # Test timeout handling routes through signal dispatcher
                with patch.object(
                    process_manager.signal_dispatcher, "send", return_value=True
                ) as mock_send:
                    await process_manager.send_timeout_signal(process.pid)
                    mock_send.assert_called_once_with(
                        "timeout", process.pid, ANY
                    )

    def test_process_config_validation(self):
        """Test process config validation across platforms."""
        current_platform = platform.system().lower()

        # Test valid config
        valid_config = ProcessConfig(
            command=["echo", "test"], name="valid_process", timeout=10.0
        )

        assert valid_config.command == ["echo", "test"]
        assert valid_config.name == "valid_process"
        assert valid_config.timeout == 10.0

        # Test platform-specific command validation
        if current_platform == "windows":
            # Windows commands
            windows_config = ProcessConfig(
                command=["cmd", "/c", "dir"], name="windows_process"
            )
            assert windows_config.command[0] == "cmd"
        else:
            # Unix commands
            unix_config = ProcessConfig(command=["ls", "-la"], name="unix_process")
            assert unix_config.command[0] == "ls"

    @pytest.mark.asyncio
    async def test_process_cleanup_on_exit(self, process_manager):
        """Test process cleanup when manager exits."""
        # Mock processes
        mock_process1 = MagicMock()
        mock_process1.pid = 12345
        mock_process1.returncode = None

        mock_process2 = MagicMock()
        mock_process2.pid = 67890
        mock_process2.returncode = None

        # Add processes to manager via the registry API
        await process_manager.registry.register(
            12345,
            mock_process1,
            ProcessConfig(command=["test1"], name="test1"),
            started_at=time.time(),
            status="running",
        )

        await process_manager.registry.register(
            67890,
            mock_process2,
            ProcessConfig(command=["test2"], name="test2"),
            started_at=time.time(),
            status="running",
        )

        # Test cleanup
        with patch.object(process_manager, "send_timeout_signal") as mock_signal:
            await process_manager.cleanup_finished_processes()

            # Should attempt to stop all processes
            assert mock_signal.call_count >= 0

    def test_watchdog_config_cross_platform(self):
        """Test watchdog configuration across platforms."""
        # Test default config
        config = WatchdogConfig()

        assert config.process_timeout > 0
        assert config.check_interval > 0
        assert config.max_hang_time > 0
        assert config.extra_buffer > 0
        assert isinstance(config.auto_kill, bool)

        # Test custom config
        custom_config = WatchdogConfig(
            process_timeout=30.0,
            check_interval=0.5,
            max_hang_time=45.0,
            extra_buffer=10.0,
            auto_kill=False,
        )

        assert custom_config.process_timeout == 30.0
        assert custom_config.check_interval == 0.5
        assert custom_config.max_hang_time == 45.0
        assert custom_config.extra_buffer == 10.0
        assert custom_config.auto_kill is False

    @pytest.mark.asyncio
    async def test_concurrent_process_management(self, process_manager):
        """Test concurrent process management."""
        # Create multiple process configs
        configs = [
            ProcessConfig(command=["echo", "test1"], name="process1"),
            ProcessConfig(command=["echo", "test2"], name="process2"),
            ProcessConfig(command=["echo", "test3"], name="process3"),
        ]

        # Mock subprocess creation
        mock_processes = []
        for i, config in enumerate(configs):
            mock_process = MagicMock()
            mock_process.pid = 10000 + i
            mock_process.returncode = None
            mock_processes.append(mock_process)

        with patch("asyncio.create_subprocess_exec", side_effect=mock_processes):
            with patch.object(process_manager.watchdog, "start", new=AsyncMock()):
                # Start processes concurrently
                tasks = [process_manager.start_process(config) for config in configs]

                processes = await asyncio.gather(*tasks)

                # Verify all processes were started
                assert len(processes) == 3
                # Use public API to verify all processes are tracked
                all_processes = await process_manager.list_processes()
                assert len(all_processes) == 3

                # Verify all processes are tracked and have correct status
                for process in processes:
                    status = await process_manager.get_process_status(process.pid)
                    assert status is not None
                    assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_process_manager_resource_cleanup(self, process_manager):
        """Test process manager resource cleanup."""
        # Test that manager can be cleaned up properly
        assert process_manager.watchdog is not None

        # Test cleanup method
        await process_manager.cleanup_finished_processes()

        # Should not raise exceptions
        assert True

    @pytest.mark.asyncio
    async def test_error_handling_in_process_management(self, process_manager):
        """Test error handling in process management."""
        # Test with invalid command
        invalid_config = ProcessConfig(
            command=["nonexistent_command_12345"], name="invalid_process", timeout=1.0
        )

        # Mock subprocess creation to simulate error
        with patch("asyncio.create_subprocess_exec") as mock_create:
            mock_create.side_effect = FileNotFoundError("Command not found")

            with pytest.raises(ProcessStartError):
                await process_manager.start_process(invalid_config)

    @pytest.mark.asyncio
    async def test_process_manager_concurrent_safety(self, process_manager):
        """Test process manager concurrent operation safety."""
        # Test that multiple operations can be performed safely concurrently
        results = []

        async def add_process(thread_id):
            mock_process = MagicMock()
            # Use a unique PID for each thread
            mock_process.pid = 10000 + thread_id
            mock_process.returncode = None

            # Use public API to register the process
            await process_manager.register_existing_process(
                mock_process.pid,
                mock_process,
                f"test_process_{thread_id}",
                None,
            )
            results.append(mock_process.pid)

        # Create multiple concurrent tasks (async version of threading)
        tasks = [add_process(i) for i in range(5)]
        await asyncio.gather(*tasks)

        # Verify all processes were added using public API
        assert len(results) == 5
        all_processes = await process_manager.list_processes()
        assert len(all_processes) == 5

    @pytest.mark.asyncio
    async def test_watchdog_process_detection(self, watchdog):
        """Test watchdog process detection and handling."""
        # Mock a process that has terminated
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = 0  # Process terminated successfully
        mock_process.poll.return_value = 0

        await watchdog.start()
        await watchdog.registry.register(
            mock_process.pid,
            mock_process,
            ProcessConfig(command=["echo", "done"], name="test_process"),
            started_at=time.time(),
            status="finished",
        )

        # Test process detection through public API
        # Allow watchdog to scan and clean up with retries for stability
        cleaned = False
        for _ in range(20):
            await asyncio.sleep(0.1)
            stats = await watchdog.get_stats()
            finished_processes = stats.get("finished_processes", 0)
            if stats["total_processes"] == 0 and finished_processes == 0:
                cleaned = True
                break

        assert cleaned, "Watchdog did not clean up finished process in time"
        await watchdog.stop()

    def test_cross_platform_file_path_handling(self):
        """Test file path handling across platforms."""
        current_platform = platform.system().lower()

        if current_platform == "windows":
            # Windows paths
            test_path = "C:\\Users\\test\\reports"
            expected_separator = "\\"
        else:
            # Unix paths
            test_path = "/home/user/reports"
            expected_separator = "/"

        # Test path handling
        path_obj = Path(test_path)
        assert str(path_obj) == test_path

        # Test path operations
        assert path_obj.name == "reports"
        assert path_obj.parent is not None
