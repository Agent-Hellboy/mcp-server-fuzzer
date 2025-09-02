import asyncio
import os
import signal
import subprocess
import time
from unittest.mock import patch, MagicMock, AsyncMock, call

import pytest

# Import the classes to test
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.watchdog import WatchdogConfig


class TestProcessManager:
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        self.manager = ProcessManager(self.config)
        self.mock_process = MagicMock(spec=subprocess.Popen)
        self.mock_process.pid = 12345
        self.mock_process.returncode = None
        return self.manager

    @pytest.mark.asyncio
    async def test_start_process_success(self):
        """Test starting a process successfully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(return_value=self.mock_process),
        ) as mock_create_subprocess:
            # Mock watchdog.start() since it's called within start_process
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    assert process == self.mock_process
                    assert process.pid in self.manager._processes
                    assert (
                        self.manager._processes[process.pid]["config"] == process_config
                    )
                    assert self.manager._processes[process.pid]["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_process_failure(self):
        """Test starting a process that fails."""
        process_config = ProcessConfig(command=["invalid_command"], name="test_process")
        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=Exception("Failed to start")),
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with pytest.raises(Exception, match="Failed to start"):
                    await self.manager.start_process(process_config)

    @pytest.mark.asyncio
    async def test_process_creation_args(self):
        """Test process creation arguments."""
        process_config = ProcessConfig(
            command=["echo", "test"],
            cwd="/tmp",
            env={"TEST": "1"},
            name="test_process",
        )

        mock_process = AsyncMock()
        mock_process.pid = 12345

        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ) as mock_create:
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    await self.manager.start_process(process_config)

                    # Check that create_subprocess_exec was called with correct args
                    mock_create.assert_called_once()
                    call_args = mock_create.call_args

                    # First args should be the command
                    assert call_args[0][0] == "echo"
                    assert call_args[0][1] == "test"

                    # Check kwargs
                    kwargs = call_args[1]
                    assert kwargs["cwd"] == "/tmp"
                    assert "TEST" in kwargs["env"]
                    assert kwargs["env"]["TEST"] == "1"

    @pytest.mark.asyncio
    async def test_stop_process_graceful(self):
        """Test stopping a process gracefully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup the test process
        mock_process = AsyncMock()
        mock_process.pid = 12345

        # Mock the process creation
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Now mock the process termination
                    with patch.object(
                        self.manager.watchdog, "unregister_process", AsyncMock()
                    ):
                        # Mock terminate and wait
                        process.terminate = MagicMock()
                        process.wait = AsyncMock(return_value=0)

                        result = await self.manager.stop_process(
                            process.pid, force=False
                        )

                        # Verify results
                        assert result is True
                        process.terminate.assert_called_once()
                        assert (
                            self.manager._processes[process.pid]["status"] == "stopped"
                        )

    @pytest.mark.asyncio
    async def test_stop_process_force(self):
        """Test stopping a process forcefully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup the test process
        mock_process = AsyncMock()
        mock_process.pid = 12345

        # Mock the process creation
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Now mock the process termination
                    with patch.object(
                        self.manager.watchdog, "unregister_process", AsyncMock()
                    ):
                        # Mock kill
                        process.kill = MagicMock()

                        result = await self.manager.stop_process(
                            process.pid, force=True
                        )

                        # Verify results
                        assert result is True
                        process.kill.assert_called_once()
                        assert (
                            self.manager._processes[process.pid]["status"] == "stopped"
                        )

    @pytest.mark.asyncio
    async def test_stop_process_not_found(self):
        """Test stopping a non-existent process."""
        result = await self.manager.stop_process(99999, force=False)
        assert result is False

    # Note: We don't need to test the internal force_kill_process and
    # graceful_terminate_process
    # methods anymore since they were removed in favor of async implementation

    @pytest.mark.asyncio
    async def test_stop_all_processes(self):
        """Test stopping all processes."""
        process_config1 = ProcessConfig(command=["echo", "test1"], name="test_process1")
        process_config2 = ProcessConfig(command=["echo", "test2"], name="test_process2")

        # Create two different mock processes with different PIDs
        mock_process1 = AsyncMock()
        mock_process1.pid = 12345
        mock_process1.returncode = None
        mock_process1.terminate = MagicMock()
        mock_process1.wait = AsyncMock(return_value=0)

        mock_process2 = AsyncMock()
        mock_process2.pid = 12346
        mock_process2.returncode = None
        mock_process2.terminate = MagicMock()
        mock_process2.wait = AsyncMock(return_value=0)

        with patch(
            "asyncio.create_subprocess_exec", side_effect=[mock_process1, mock_process2]
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    # Start both processes
                    proc1 = await self.manager.start_process(process_config1)
                    proc2 = await self.manager.start_process(process_config2)

                    # Verify both processes are tracked with different PIDs
                    assert proc1.pid != proc2.pid

                    # Now test stopping all processes
                    with patch.object(
                        self.manager.watchdog, "unregister_process", AsyncMock()
                    ):
                        await self.manager.stop_all_processes(force=False)

                        # Verify each process was terminated
                        mock_process1.terminate.assert_called_once()
                        mock_process2.terminate.assert_called_once()

                        # Verify both processes are marked as stopped
                        assert self.manager._processes[proc1.pid]["status"] == "stopped"
                        assert self.manager._processes[proc2.pid]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_get_process_status_running(self):
        """Test getting status of a running process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Get status
                    status = await self.manager.get_process_status(process.pid)

                    # Verify status
                    assert status is not None
                    assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_process_status_finished(self):
        """Test getting status of a finished process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process with returncode to simulate finished process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Get status
                    status = await self.manager.get_process_status(process.pid)

                    # Verify status
                    assert status is not None
                    assert status["status"] == "finished"
                    assert status["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_get_process_status_not_found(self):
        """Test getting status of a non-existent process."""
        status = await self.manager.get_process_status(99999)
        assert status is None

    @pytest.mark.asyncio
    async def test_list_processes(self):
        """Test listing all managed processes."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    await self.manager.start_process(process_config)

                    # List processes
                    processes = await self.manager.list_processes()

                    # Verify processes list
                    assert len(processes) == 1
                    assert processes[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_wait_for_process_success(self):
        """Test waiting for a process to complete successfully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.wait = AsyncMock(return_value=0)

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Wait for process
                    returncode = await self.manager.wait_for_process(process.pid)

                    # Verify return code
                    assert returncode == 0
                    mock_process.wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_wait_for_process_timeout(self):
        """Test waiting for a process with timeout."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process with wait that raises TimeoutExpired
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.wait = AsyncMock(side_effect=asyncio.TimeoutError())

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Wait for process with timeout
                    returncode = await self.manager.wait_for_process(
                        process.pid, timeout=1.0
                    )

                    # Verify timeout handling
                    assert returncode is None
                    mock_process.wait.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_activity(self):
        """Test updating activity timestamp for a process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Test update_activity
                    with patch.object(
                        self.manager.watchdog, "update_activity", new=AsyncMock()
                    ) as mock_update:
                        await self.manager.update_activity(process.pid)
                        mock_update.assert_called_once_with(process.pid)

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting overall statistics about managed processes."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    await self.manager.start_process(process_config)

                    # Mock watchdog stats
                    with patch.object(
                        self.manager.watchdog,
                        "get_stats",
                        new=AsyncMock(return_value={"test": "stats"}),
                    ):
                        # Get stats
                        stats = await self.manager.get_stats()

                        # Verify stats content
                        assert "processes" in stats
                        assert stats["total_managed"] == 1
                        assert "watchdog" in stats

    @pytest.mark.asyncio
    async def test_cleanup_finished_processes(self):
        """Test cleaning up finished processes."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process with returncode to simulate finished process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Clean up finished processes
                    with patch.object(
                        self.manager.watchdog, "unregister_process", AsyncMock()
                    ):
                        cleaned = await self.manager.cleanup_finished_processes()

                        # Verify cleanup
                        assert cleaned == 1
                        assert process.pid not in self.manager._processes

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test shutting down the process manager."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    await self.manager.start_process(process_config)

                    # Test shutdown
                    with patch.object(
                        self.manager, "stop_all_processes", AsyncMock()
                    ) as mock_stop_all:
                        with patch.object(
                            self.manager.watchdog, "stop", AsyncMock()
                        ) as mock_watchdog_stop:
                            await self.manager.shutdown()

                            # Verify shutdown calls
                            mock_stop_all.assert_called_once()
                            mock_watchdog_stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal(self):
        """Test sending a timeout signal to a process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.terminate = MagicMock()

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Mock os.name to use Windows path (ensures terminate() is called)
                    with patch("os.name", "nt"):
                        # Test send_timeout_signal
                        result = await self.manager.send_timeout_signal(
                            process.pid, signal_type="timeout"
                        )

                        # Verify signal was sent
                        assert result is True
                        mock_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal_to_all(self):
        """Test sending a timeout signal to all processes."""
        process_config1 = ProcessConfig(command=["echo", "test1"], name="test_process1")
        process_config2 = ProcessConfig(command=["echo", "test2"], name="test_process2")

        # Create two different mock processes with different PIDs
        mock_process1 = AsyncMock()
        mock_process1.pid = 12345
        mock_process1.returncode = None
        mock_process1.terminate = MagicMock()

        mock_process2 = AsyncMock()
        mock_process2.pid = 12346
        mock_process2.returncode = None
        mock_process2.terminate = MagicMock()

        # Mock process creation
        with patch(
            "asyncio.create_subprocess_exec", side_effect=[mock_process1, mock_process2]
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    # Start both processes
                    proc1 = await self.manager.start_process(process_config1)
                    proc2 = await self.manager.start_process(process_config2)

                    # Verify both processes are tracked with different PIDs
                    assert proc1.pid != proc2.pid

                    # Mock os.name to use Windows path (ensures terminate() is called)
                    with patch("os.name", "nt"):
                        # Test sending signal to all processes
                        results = await self.manager.send_timeout_signal_to_all(
                            signal_type="timeout"
                        )

                        # Verify results
                        assert len(results) == 2
                        assert results[proc1.pid] is True
                        assert results[proc2.pid] is True
                        mock_process1.terminate.assert_called_once()
                        mock_process2.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_process_registered(self):
        """Test checking if a process is registered with the watchdog."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")

        # Setup mock process
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Start the process
        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    process = await self.manager.start_process(process_config)

                    # Test is_process_registered
                    with patch.object(
                        self.manager.watchdog,
                        "is_process_registered",
                        new=AsyncMock(return_value=True),
                    ):
                        result = await self.manager.is_process_registered(process.pid)
                        assert result is True

    @pytest.mark.asyncio
    async def test_register_existing_process(self):
        """Test registering an existing process with the manager."""
        activity_callback = MagicMock()
        with patch.object(
            self.manager.watchdog, "register_process", AsyncMock()
        ) as mock_register:
            await self.manager.register_existing_process(
                self.mock_process.pid,
                self.mock_process,
                "existing_process",
                activity_callback,
            )
            mock_register.assert_called_once_with(
                self.mock_process.pid,
                self.mock_process,
                activity_callback,
                "existing_process",
            )
            assert self.mock_process.pid in self.manager._processes
            assert (
                self.manager._processes[self.mock_process.pid]["config"].name
                == "existing_process"
            )


if __name__ == "__main__":
    pytest.main(["-v", "--asyncio-mode=auto"])
