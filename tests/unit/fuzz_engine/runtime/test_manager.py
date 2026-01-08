import asyncio
import os
import signal
import subprocess
import time
from unittest.mock import patch, MagicMock, AsyncMock, call

import pytest

# Import the classes to test
from mcp_fuzzer.exceptions import (
    ProcessSignalError,
    ProcessStartError,
    ProcessStopError,
)
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime import WatchdogConfig, ProcessWatchdog


class TestProcessManager:
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.config = WatchdogConfig(process_timeout=1.0, check_interval=0.1)
        self.manager = ProcessManager.from_config(self.config)
        # Backwards-compat shims for mocked watchdog attributes used in older tests
        self.manager.watchdog.register_process = AsyncMock()
        self.manager.watchdog.unregister_process = AsyncMock()
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
                process = await self.manager.start_process(process_config)

                assert process == self.mock_process
                # Use public API to verify process is registered
                status = await self.manager.get_process_status(process.pid)
                assert status is not None
                assert status["config"] == process_config
                assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_process_failure(self):
        """Test starting a process that fails."""
        process_config = ProcessConfig(command=["invalid_command"], name="test_process")
        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=Exception("Failed to start")),
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with pytest.raises(ProcessStartError) as exc:
                    await self.manager.start_process(process_config)
                assert exc.value.code == "95002"

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
                        # Use public API to verify status (unregistered after stop)
                        status = await self.manager.get_process_status(process.pid)
                        assert status is None

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
                        # Use public API to verify status (unregistered after stop)
                        status = await self.manager.get_process_status(process.pid)
                        assert status is None

    @pytest.mark.asyncio
    async def test_stop_process_not_found(self):
        """Test stopping a non-existent process."""
        result = await self.manager.stop_process(99999, force=False)
        assert result is False

    @pytest.mark.asyncio
    async def test_stop_process_error_propagates_exception(self):
        """Test that stop_process raises ProcessStopError on failure."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        # Register a running process in the registry
        await self.manager.registry.register(
            mock_process.pid,
            mock_process,
            ProcessConfig(command=["echo"], name="test_process"),
            started_at=time.time(),
            status="running",
        )

        # Test error handling through public API
        # Mock the signal dispatcher to raise an error during graceful termination
        with (
            patch.object(self.manager.watchdog, "unregister_process", AsyncMock()),
            patch.object(
                self.manager.signal_dispatcher,
                "send",
                AsyncMock(side_effect=RuntimeError("boom")),
            ),
        ):
            with pytest.raises(ProcessStopError) as exc:
                await self.manager.stop_process(mock_process.pid, force=False)
            assert exc.value.code == "95003"

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

                        # Verify both processes are removed from tracking
                        proc1_status = await self.manager.get_process_status(proc1.pid)
                        proc2_status = await self.manager.get_process_status(proc2.pid)
                        assert proc1_status is None
                        assert proc2_status is None

    @pytest.mark.asyncio
    async def test_stop_all_processes_failure(self):
        """Ensure stop_all_processes raises ProcessStopError when any stop fails."""
        with patch.object(
            self.manager.lifecycle,
            "stop_all",
            new=AsyncMock(side_effect=ProcessStopError("fail", context={"pid": 1})),
        ):
            with pytest.raises(ProcessStopError):
                await self.manager.stop_all_processes()

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
                    process.returncode = 0

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
        mock_process.returncode = None

        async def wait_side_effect(*args, **kwargs):
            mock_process.returncode = 0
            return 0

        mock_process.wait = AsyncMock(side_effect=wait_side_effect)

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
                    result = await self.manager.wait(process.pid)

                    # Verify completion result
                    assert result is not None
                    assert result.exit_code == 0
                    assert result.timed_out is False
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
                    completion = await self.manager.wait(process.pid, timeout=1.0)

                    # Verify timeout handling
                    assert completion is not None
                    assert completion.exit_code is None
                    assert completion.timed_out is True
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
                    process.returncode = 0

                    # Clean up finished processes
                    with patch.object(
                        self.manager.watchdog, "unregister_process", AsyncMock()
                    ):
                        cleaned = await self.manager.cleanup_finished_processes()

                        # Verify cleanup using public API
                        assert cleaned == 1
                        status = await self.manager.get_process_status(process.pid)
                        assert status is None

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
    async def test_send_timeout_signal_error(self):
        """Test send_timeout_signal raises ProcessSignalError on failure."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        await self.manager.registry.register(
            mock_process.pid,
            mock_process,
            ProcessConfig(command=["echo"], name="test_process"),
            started_at=time.time(),
            status="running",
        )

        with patch.object(
            self.manager.signal_dispatcher,
            "send",
            AsyncMock(side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(ProcessSignalError) as exc:
                await self.manager.send_timeout_signal(mock_process.pid, "timeout")
            assert exc.value.code == "95004"

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
    async def test_send_timeout_signal_to_all_failure(self):
        """Raise ProcessSignalError when any PID fails in bulk signal."""
        with patch.object(
            self.manager,
            "send_timeout_signal",
            new=AsyncMock(
                side_effect=[
                    True,
                    ProcessSignalError("bad", context={"pid": 2}),
                ]
            ),
        ):
            await self.manager.registry.register(
                1, MagicMock(), ProcessConfig(command=["echo"])
            )
            await self.manager.registry.register(
                2, MagicMock(), ProcessConfig(command=["echo"])
            )
            with pytest.raises(ProcessSignalError):
                await self.manager.send_timeout_signal_to_all()

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
                process = await self.manager.start_process(process_config)
                result = await self.manager.is_process_registered(process.pid)
                assert result is True

    @pytest.mark.asyncio
    async def test_register_existing_process(self):
        """Test registering an existing process with the manager."""
        activity_callback = MagicMock()
        await self.manager.register_existing_process(
            self.mock_process.pid,
            self.mock_process,
            "existing_process",
            activity_callback,
        )
        # Use public API to verify process is registered
        status = await self.manager.get_process_status(self.mock_process.pid)
        assert status is not None
        assert status["config"].name == "existing_process"

    @pytest.mark.asyncio
    async def test_observer_callback(self):
        """Test that observer callbacks are called on events."""
        events_received = []

        def observer_callback(event_name: str, data: dict):
            events_received.append((event_name, data))

        self.manager.add_observer(observer_callback)

        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    await self.manager.start_process(process_config)

                    # Should have received "started" event
                    assert len(events_received) > 0
                    assert events_received[0][0] == "started"
                    assert events_received[0][1]["process_name"] == "test_process"

    @pytest.mark.asyncio
    async def test_observer_error_handling(self):
        """Test that observer errors are handled gracefully."""

        def failing_observer(event_name: str, data: dict):
            raise Exception("Observer error")

        def working_observer(event_name: str, data: dict):
            pass

        self.manager.add_observer(failing_observer)
        self.manager.add_observer(working_observer)

        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        with patch(
            "asyncio.create_subprocess_exec", new=AsyncMock(return_value=mock_process)
        ):
            with patch.object(self.manager.watchdog, "start", AsyncMock()):
                with patch.object(
                    self.manager.watchdog, "register_process", AsyncMock()
                ):
                    # Should not raise, even if one observer fails
                    await self.manager.start_process(process_config)

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_found(self):
        """Test send_timeout_signal with process not found."""
        result = await self.manager.send_timeout_signal(99999)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_already_exited(self):
        """Test send_timeout_signal with process that already exited."""
        mock_process = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = 0

        await self.manager.registry.register(
            mock_process.pid,
            mock_process,
            ProcessConfig(command=["echo"], name="test_process"),
            started_at=time.time(),
            status="finished",
        )

        result = await self.manager.send_timeout_signal(mock_process.pid)
        assert result is False

    @pytest.mark.asyncio
    async def test_send_timeout_signal_to_all_empty(self):
        """Test send_timeout_signal_to_all with no processes."""
        results = await self.manager.send_timeout_signal_to_all()
        assert results == {}

    @pytest.mark.asyncio
    async def test_send_timeout_signal_to_all_with_exceptions(self):
        """Test send_timeout_signal_to_all handles exceptions properly."""
        mock_process1 = AsyncMock()
        mock_process1.pid = 11111
        mock_process1.returncode = None

        mock_process2 = AsyncMock()
        mock_process2.pid = 22222
        mock_process2.returncode = None

        await self.manager.registry.register(
            mock_process1.pid,
            mock_process1,
            ProcessConfig(command=["test1"], name="test1"),
        )
        await self.manager.registry.register(
            mock_process2.pid,
            mock_process2,
            ProcessConfig(command=["test2"], name="test2"),
        )

        # Make one succeed, one fail
        call_count = 0

        async def mock_send(pid, signal_type="timeout"):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return True
            raise RuntimeError("Signal failed")

        with patch.object(self.manager, "send_timeout_signal", side_effect=mock_send):
            with pytest.raises(ProcessSignalError) as exc_info:
                await self.manager.send_timeout_signal_to_all()

            assert "Failed to send" in str(exc_info.value)
            assert len(exc_info.value.context["failed_processes"]) == 1

    def test_wiring_logic_in_init(self):
        """Test that ProcessManager.__init__ correctly wires watchdog references."""
        from mcp_fuzzer.fuzz_engine.runtime import (
            ProcessLifecycle,
            ProcessInspector,
            ProcessRegistry,
            SignalDispatcher,
            WatchdogConfig,
        )
        import logging

        logger = logging.getLogger(__name__)
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(registry, logger)
        watchdog = ProcessWatchdog(registry, signal_handler, WatchdogConfig())

        # Create lifecycle and monitor with different watchdog instances
        different_watchdog = ProcessWatchdog(registry, signal_handler, WatchdogConfig())
        lifecycle = ProcessLifecycle(
            different_watchdog, registry, signal_handler, logger
        )
        monitor = ProcessInspector(registry, different_watchdog, logger)

        # Create manager - should wire them to use the same watchdog
        manager = ProcessManager.with_dependencies(
            watchdog, registry, signal_handler, lifecycle, monitor, logger
        )

        # Verify wiring
        assert manager.lifecycle.watchdog is manager.watchdog
        assert manager.monitor.watchdog is manager.watchdog

    def test_watchdog_assignment_keeps_components_in_sync(self):
        """Reassigning ``watchdog`` keeps lifecycle/monitor references aligned."""
        from mcp_fuzzer.fuzz_engine.runtime import (
            ProcessLifecycle,
            ProcessInspector,
            ProcessRegistry,
            SignalDispatcher,
            WatchdogConfig,
        )
        import logging

        logger = logging.getLogger(__name__)
        registry = ProcessRegistry()
        signal_handler = SignalDispatcher(registry, logger)
        watchdog = ProcessWatchdog(registry, signal_handler, WatchdogConfig())
        lifecycle = ProcessLifecycle(watchdog, registry, signal_handler, logger)
        monitor = ProcessInspector(registry, watchdog, logger)

        manager = ProcessManager.with_dependencies(
            watchdog, registry, signal_handler, lifecycle, monitor, logger
        )

        new_watchdog = ProcessWatchdog(registry, signal_handler, WatchdogConfig())
        manager.watchdog = new_watchdog

        assert manager.watchdog is new_watchdog
        assert manager.lifecycle.watchdog is new_watchdog
        assert manager.monitor.watchdog is new_watchdog

    @pytest.mark.asyncio
    async def test_shutdown_with_exception(self):
        """Test shutdown handles exceptions in stop_all_processes."""
        with patch.object(
            self.manager, "stop_all_processes", side_effect=Exception("Stop failed")
        ) as mock_stop:
            with patch.object(
                self.manager.watchdog, "stop", AsyncMock()
            ) as mock_watchdog_stop:
                with patch.object(
                    self.manager.registry, "clear", AsyncMock()
                ) as mock_clear:
                    with pytest.raises(Exception, match="Stop failed"):
                        await self.manager.shutdown()

                    # Should still call cleanup in finally block
                    mock_watchdog_stop.assert_called_once()
                    mock_clear.assert_called_once()


if __name__ == "__main__":
    pytest.main(["-v", "--asyncio-mode=auto"])
