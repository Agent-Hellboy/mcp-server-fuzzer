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
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            assert process == self.mock_process
            assert process.pid in self.manager._processes
            assert self.manager._processes[process.pid]["config"] == process_config
            assert self.manager._processes[process.pid]["status"] == "running"

    @pytest.mark.asyncio
    async def test_start_process_failure(self):
        """Test starting a process that fails."""
        process_config = ProcessConfig(command=["invalid_command"], name="test_process")
        with patch.object(
            self.manager,
            "_start_process_sync",
            side_effect=Exception("Failed to start"),
        ):
            with pytest.raises(Exception, match="Failed to start"):
                await self.manager.start_process(process_config)

    def test_start_process_sync(self):
        """Test synchronous process start method."""
        process_config = ProcessConfig(
            command=["echo", "test"],
            cwd="/tmp",
            env={"TEST": "1"},
            name="test_process",
        )
        with patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = self.mock_process
            process = self.manager._start_process_sync(process_config)
            assert process == self.mock_process
            mock_popen.assert_called_once()
            args, kwargs = mock_popen.call_args
            assert args[0] == ["echo", "test"]
            assert kwargs["cwd"] == "/tmp"
            assert "TEST" in kwargs["env"]
            assert kwargs["env"]["TEST"] == "1"

    @pytest.mark.asyncio
    async def test_stop_process_graceful(self):
        """Test stopping a process gracefully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(
                self.manager, "_graceful_terminate_process"
            ) as mock_terminate:
                result = await self.manager.stop_process(process.pid, force=False)
                assert result is True
                mock_terminate.assert_called_once_with(
                    process.pid, process, "test_process"
                )
                assert self.manager._processes[process.pid]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_stop_process_force(self):
        """Test stopping a process forcefully."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(self.manager, "_force_kill_process") as mock_kill:
                result = await self.manager.stop_process(process.pid, force=True)
                assert result is True
                mock_kill.assert_called_once_with(process.pid, process, "test_process")
                assert self.manager._processes[process.pid]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_stop_process_not_found(self):
        """Test stopping a non-existent process."""
        result = await self.manager.stop_process(99999, force=False)
        assert result is False

    def test_force_kill_process_unix(self):
        """Test force killing a process on Unix-like systems."""
        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    self.manager._force_kill_process(
                        self.mock_process.pid, self.mock_process, "test_process"
                    )
                    mock_killpg.assert_called_once_with(12345, signal.SIGKILL)

    def test_force_kill_process_windows(self):
        """Test force killing a process on Windows."""
        with patch("os.name", "nt"):
            self.manager._force_kill_process(
                self.mock_process.pid, self.mock_process, "test_process"
            )
            self.mock_process.kill.assert_called_once()

    def test_graceful_terminate_process_unix_success(self):
        """Test graceful termination of a process on Unix-like systems with success."""
        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    with patch.object(self.mock_process, "wait", return_value=0):
                        self.manager._graceful_terminate_process(
                            self.mock_process.pid,
                            self.mock_process,
                            "test_process",
                        )
                        mock_killpg.assert_called_once_with(12345, signal.SIGTERM)
                        self.mock_process.wait.assert_called_once_with(timeout=2.0)

    def test_graceful_terminate_process_unix_timeout(self):
        """Test graceful termination of a process on Unix-like systems with timeout."""
        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    # We need to handle two wait calls:
                    # 1. Initial wait with 2.0 timeout (times out)
                    # 2. Second wait after force kill with 1.0 timeout
                    mock_wait = MagicMock(
                        side_effect=[
                            subprocess.TimeoutExpired(cmd=["test"], timeout=2.0),
                            None,  # Second wait succeeds
                        ]
                    )
                    self.mock_process.wait = mock_wait

                    with patch.object(
                        self.manager, "_force_kill_process"
                    ) as mock_force_kill:
                        self.manager._graceful_terminate_process(
                            self.mock_process.pid,
                            self.mock_process,
                            "test_process",
                        )
                        mock_killpg.assert_called_once_with(12345, signal.SIGTERM)

                        # Verify first wait call
                        assert mock_wait.call_args_list[0] == call(timeout=2.0)

                        mock_force_kill.assert_called_once_with(
                            self.mock_process.pid,
                            self.mock_process,
                            "test_process",
                        )

                        # Verify second wait call
                        assert mock_wait.call_args_list[1] == call(timeout=1.0)

    @pytest.mark.asyncio
    async def test_stop_all_processes(self):
        """Test stopping all processes."""
        process_config1 = ProcessConfig(command=["echo", "test1"], name="test_process1")
        process_config2 = ProcessConfig(command=["echo", "test2"], name="test_process2")

        # Create two different mock processes with different PIDs
        mock_process1 = MagicMock(spec=subprocess.Popen)
        mock_process1.pid = 12345
        mock_process1.returncode = None

        mock_process2 = MagicMock(spec=subprocess.Popen)
        mock_process2.pid = 12346
        mock_process2.returncode = None

        # Use side_effect to return different processes for different calls
        with patch.object(
            self.manager,
            "_start_process_sync",
            side_effect=[mock_process1, mock_process2],
        ):
            proc1 = await self.manager.start_process(process_config1)
            proc2 = await self.manager.start_process(process_config2)

            # Verify both processes are tracked with different PIDs
            assert proc1.pid != proc2.pid

            with patch.object(
                self.manager, "_graceful_terminate_process"
            ) as mock_terminate:
                await self.manager.stop_all_processes(force=False)
                assert mock_terminate.call_count == 2
                assert self.manager._processes[proc1.pid]["status"] == "stopped"
                assert self.manager._processes[proc2.pid]["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_get_process_status_running(self):
        """Test getting status of a running process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            status = await self.manager.get_process_status(process.pid)
            assert status is not None
            assert status["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_process_status_finished(self):
        """Test getting status of a finished process."""
        self.mock_process.returncode = 0
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            status = await self.manager.get_process_status(process.pid)
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
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            await self.manager.start_process(process_config)
            processes = await self.manager.list_processes()
            assert len(processes) == 1
            assert processes[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_wait_for_process_success(self):
        """Test waiting for a process to complete successfully."""
        self.mock_process.returncode = 0
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(self.mock_process, "wait", return_value=0):
                returncode = await self.manager.wait_for_process(process.pid)
                assert returncode == 0

    @pytest.mark.asyncio
    async def test_wait_for_process_timeout(self):
        """Test waiting for a process with timeout."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(
                self.mock_process,
                "wait",
                side_effect=subprocess.TimeoutExpired(cmd=["test"], timeout=1.0),
            ):
                returncode = await self.manager.wait_for_process(
                    process.pid, timeout=1.0
                )
                assert returncode is None

    @pytest.mark.asyncio
    async def test_update_activity(self):
        """Test updating activity timestamp for a process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(self.manager.watchdog, "update_activity") as mock_update:
                await self.manager.update_activity(process.pid)
                mock_update.assert_called_once_with(process.pid)

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test getting overall statistics about managed processes."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            await self.manager.start_process(process_config)
            stats = await self.manager.get_stats()
            assert "processes" in stats
            assert stats["total_managed"] == 1
            assert "watchdog" in stats

    @pytest.mark.asyncio
    async def test_cleanup_finished_processes(self):
        """Test cleaning up finished processes."""
        self.mock_process.returncode = 0
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            cleaned = await self.manager.cleanup_finished_processes()
            assert cleaned == 1
            assert process.pid not in self.manager._processes

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test shutting down the process manager."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            await self.manager.start_process(process_config)
            with patch.object(self.manager, "stop_all_processes") as mock_stop_all:
                with patch.object(self.manager.watchdog, "stop") as mock_watchdog_stop:
                    await self.manager.shutdown()
                    mock_stop_all.assert_called_once()
                    mock_watchdog_stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal(self):
        """Test sending a timeout signal to a process."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(self.manager, "_send_signal_sync") as mock_send_signal:
                result = await self.manager.send_timeout_signal(
                    process.pid, signal_type="timeout"
                )
                assert result is True
                mock_send_signal.assert_called_once_with(
                    process.pid, process, "test_process", "timeout"
                )

    @pytest.mark.asyncio
    async def test_send_timeout_signal_to_all(self):
        """Test sending a timeout signal to all processes."""
        process_config1 = ProcessConfig(command=["echo", "test1"], name="test_process1")
        process_config2 = ProcessConfig(command=["echo", "test2"], name="test_process2")

        # Create two different mock processes with different PIDs
        mock_process1 = MagicMock(spec=subprocess.Popen)
        mock_process1.pid = 12345
        mock_process1.returncode = None

        mock_process2 = MagicMock(spec=subprocess.Popen)
        mock_process2.pid = 12346
        mock_process2.returncode = None

        # Use side_effect to return different processes for different calls
        with patch.object(
            self.manager,
            "_start_process_sync",
            side_effect=[mock_process1, mock_process2],
        ):
            proc1 = await self.manager.start_process(process_config1)
            proc2 = await self.manager.start_process(process_config2)

            # Verify both processes are tracked with different PIDs
            assert proc1.pid != proc2.pid

            with patch.object(self.manager, "_send_signal_sync") as mock_send_signal:
                results = await self.manager.send_timeout_signal_to_all(
                    signal_type="timeout"
                )
                assert len(results) == 2
                assert results[proc1.pid] is True
                assert results[proc2.pid] is True
                assert mock_send_signal.call_count == 2

    @pytest.mark.asyncio
    async def test_is_process_registered(self):
        """Test checking if a process is registered with the watchdog."""
        process_config = ProcessConfig(command=["echo", "test"], name="test_process")
        with patch.object(
            self.manager, "_start_process_sync", return_value=self.mock_process
        ):
            process = await self.manager.start_process(process_config)
            with patch.object(
                self.manager.watchdog,
                "is_process_registered",
                return_value=True,
            ):
                result = await self.manager.is_process_registered(process.pid)
                assert result is True

    def test_register_existing_process(self):
        """Test registering an existing process with the manager."""
        activity_callback = MagicMock()
        with patch.object(self.manager.watchdog, "register_process") as mock_register:
            self.manager.register_existing_process(
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
