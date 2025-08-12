"""
Tests for the Process Management system.
"""

import pytest
import time
import subprocess
from unittest.mock import Mock, patch
from mcp_fuzzer.process_mgmt import (
    ProcessWatchdog,
    WatchdogConfig,
    ProcessManager,
    ProcessConfig,
    AsyncProcessWrapper,
    AsyncProcessGroup,
)


class TestWatchdogConfig:
    """Test WatchdogConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = WatchdogConfig()
        assert config.check_interval == 1.0
        assert config.process_timeout == 30.0
        assert config.extra_buffer == 5.0
        assert config.max_hang_time == 60.0
        assert config.auto_kill is True
        assert config.log_level == "WARNING"

    def test_custom_config(self):
        """Test custom configuration values."""
        config = WatchdogConfig(
            check_interval=0.5,
            process_timeout=15.0,
            extra_buffer=2.0,
            max_hang_time=30.0,
            auto_kill=False,
            log_level="DEBUG",
        )
        assert config.check_interval == 0.5
        assert config.process_timeout == 15.0
        assert config.extra_buffer == 2.0
        assert config.max_hang_time == 30.0
        assert config.auto_kill is False
        assert config.log_level == "DEBUG"


class TestProcessConfig:
    """Test ProcessConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ProcessConfig(command=["test"])
        assert config.command == ["test"]
        assert config.cwd is None
        assert config.env is None
        assert config.timeout == 30.0
        assert config.auto_kill is True
        assert config.name == "unknown"
        assert config.activity_callback is None

    def test_custom_config(self):
        """Test custom configuration values."""

        def callback():
            return time.time()

        config = ProcessConfig(
            command=["test", "arg"],
            cwd="/tmp",
            env={"TEST": "value"},
            timeout=60.0,
            auto_kill=False,
            name="test_process",
            activity_callback=callback,
        )
        assert config.command == ["test", "arg"]
        assert config.cwd == "/tmp"
        assert config.env == {"TEST": "value"}
        assert config.timeout == 60.0
        assert config.auto_kill is False
        assert config.name == "test_process"
        assert config.activity_callback == callback


class TestProcessWatchdog:
    """Test ProcessWatchdog class."""

    def test_init(self):
        """Test watchdog initialization."""
        watchdog = ProcessWatchdog()
        assert watchdog.config is not None
        assert watchdog._watchdog_thread is None
        assert watchdog._stop_event.is_set() is False
        assert len(watchdog._processes) == 0

    def test_register_unregister_process(self):
        """Test process registration and unregistration."""
        watchdog = ProcessWatchdog()
        mock_process = Mock()
        mock_process.returncode = None

        # Register process
        watchdog.register_process(123, mock_process, name="test")
        assert 123 in watchdog._processes
        assert watchdog._processes[123]["name"] == "test"

        # Unregister process
        watchdog.unregister_process(123)
        assert 123 not in watchdog._processes

    def test_update_activity(self):
        """Test activity update."""
        watchdog = ProcessWatchdog()
        mock_process = Mock()
        mock_process.returncode = None

        watchdog.register_process(123, mock_process, name="test")
        initial_time = watchdog._processes[123]["last_activity"]

        time.sleep(0.1)  # Small delay
        watchdog.update_activity(123)

        assert watchdog._processes[123]["last_activity"] > initial_time

    def test_start_stop(self):
        """Test watchdog start and stop."""
        watchdog = ProcessWatchdog()

        # Start
        watchdog.start()
        assert watchdog._watchdog_thread is not None
        assert watchdog._watchdog_thread.is_alive()

        # Stop
        watchdog.stop()
        assert watchdog._watchdog_thread is None

    def test_get_stats(self):
        """Test statistics retrieval."""
        watchdog = ProcessWatchdog()
        mock_process = Mock()
        mock_process.returncode = None

        watchdog.register_process(123, mock_process, name="test")
        stats = watchdog.get_stats()

        assert stats["total_processes"] == 1
        assert stats["running_processes"] == 1
        assert stats["finished_processes"] == 0


class TestProcessManager:
    """Test ProcessManager class."""

    @patch("subprocess.Popen")
    def test_start_process(self, mock_popen):
        """Test process starting."""
        mock_process = Mock()
        mock_process.pid = 123
        mock_popen.return_value = mock_process

        manager = ProcessManager()
        config = ProcessConfig(command=["test"], name="test_process")

        process = manager.start_process(config)

        assert process == mock_process
        assert 123 in manager._processes
        assert manager._processes[123]["config"] == config

    def test_stop_process(self):
        """Test process stopping."""
        manager = ProcessManager()

        # Mock a process
        mock_process = Mock()
        mock_process.pid = 123
        mock_process.returncode = None

        manager._processes[123] = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
            "started_at": time.time(),
            "status": "running",
        }

        # Test stopping
        result = manager.stop_process(123)
        assert result is True

    def test_get_process_status(self):
        """Test process status retrieval."""
        manager = ProcessManager()

        # Mock a process
        mock_process = Mock()
        mock_process.pid = 123
        mock_process.returncode = None

        manager._processes[123] = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
            "started_at": time.time(),
            "status": "running",
        }

        status = manager.get_process_status(123)
        assert status is not None
        assert status["config"].name == "test_process"

    def test_list_processes(self):
        """Test process listing."""
        manager = ProcessManager()

        # Mock processes
        mock_process1 = Mock()
        mock_process1.pid = 123
        mock_process1.returncode = None

        mock_process2 = Mock()
        mock_process2.pid = 456
        mock_process2.returncode = None

        manager._processes[123] = {
            "process": mock_process1,
            "config": ProcessConfig(command=["test1"], name="test1"),
            "started_at": time.time(),
            "status": "running",
        }

        manager._processes[456] = {
            "process": mock_process2,
            "config": ProcessConfig(command=["test2"], name="test2"),
            "started_at": time.time(),
            "status": "running",
        }

        processes = manager.list_processes()
        assert len(processes) == 2
        assert any(p["config"].name == "test1" for p in processes)
        assert any(p["config"].name == "test2" for p in processes)

    def test_get_stats(self):
        """Test statistics retrieval."""
        manager = ProcessManager()

        # Mock a process
        mock_process = Mock()
        mock_process.pid = 123
        mock_process.returncode = None

        manager._processes[123] = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
            "started_at": time.time(),
            "status": "running",
        }

        stats = manager.get_stats()
        assert stats["total_managed"] == 1
        assert "processes" in stats
        assert "watchdog" in stats


class TestAsyncProcessWrapper:
    """Test AsyncProcessWrapper class."""

    @pytest.mark.asyncio
    async def test_init(self):
        """Test async wrapper initialization."""
        wrapper = AsyncProcessWrapper()
        assert wrapper.process_manager is not None
        assert wrapper.executor is not None

    @pytest.mark.asyncio
    async def test_start_process(self):
        """Test async process starting."""
        wrapper = AsyncProcessWrapper()

        with patch.object(wrapper.process_manager, "start_process") as mock_start:
            mock_process = Mock()
            mock_process.pid = 123
            mock_start.return_value = mock_process

            config = ProcessConfig(command=["test"], name="test_process")
            process = await wrapper.start_process(config)

            assert process == mock_process
            mock_start.assert_called_once_with(config)

    @pytest.mark.asyncio
    async def test_stop_process(self):
        """Test async process stopping."""
        wrapper = AsyncProcessWrapper()

        with patch.object(wrapper.process_manager, "stop_process") as mock_stop:
            mock_stop.return_value = True

            result = await wrapper.stop_process(123, force=True)

            assert result is True
            mock_stop.assert_called_once_with(123, True)


class TestAsyncProcessGroup:
    """Test AsyncProcessGroup class."""

    @pytest.mark.asyncio
    async def test_init(self):
        """Test process group initialization."""
        group = AsyncProcessGroup()
        assert group.process_wrapper is not None
        assert len(group.process_configs) == 0
        assert len(group.running_processes) == 0

    @pytest.mark.asyncio
    async def test_add_process(self):
        """Test adding process to group."""
        group = AsyncProcessGroup()
        config = ProcessConfig(command=["test"], name="test_process")

        await group.add_process("test_key", config)

        assert "test_key" in group.process_configs
        assert group.process_configs["test_key"] == config

    @pytest.mark.asyncio
    async def test_start_all(self):
        """Test starting all processes in group."""
        group = AsyncProcessGroup()

        # Add processes
        config1 = ProcessConfig(command=["test1"], name="test1")
        config2 = ProcessConfig(command=["test2"], name="test2")

        await group.add_process("test1", config1)
        await group.add_process("test2", config2)

        # Mock the wrapper's start_process method
        mock_process1 = Mock()
        mock_process1.pid = 123
        mock_process2 = Mock()
        mock_process2.pid = 456

        with patch.object(group.process_wrapper, "start_process") as mock_start:
            mock_start.side_effect = [mock_process1, mock_process2]

            started = await group.start_all()

            assert len(started) == 2
            assert started["test1"] == mock_process1
            assert started["test2"] == mock_process2
            assert len(group.running_processes) == 2


if __name__ == "__main__":
    pytest.main([__file__])
