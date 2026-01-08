#!/usr/bin/env python3
"""
Unit tests for ProcessLifecycle.
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.exceptions import ProcessStartError, ProcessStopError
from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.lifecycle import (
    ProcessLifecycle,
    _format_output,
    _normalize_returncode,
)


class TestNormalizeReturncode:
    """Test _normalize_returncode helper function."""

    def test_none_value(self):
        """Test with None value."""
        assert _normalize_returncode(None) is None

    def test_integer_value(self):
        """Test with integer value."""
        assert _normalize_returncode(0) == 0
        assert _normalize_returncode(1) == 1
        assert _normalize_returncode(-1) == -1

    def test_mock_object(self):
        """Test with mock object (should return None)."""
        mock = MagicMock()
        assert _normalize_returncode(mock) is None

    def test_string_value(self):
        """Test with string value (should return None)."""
        assert _normalize_returncode("0") is None


class TestFormatOutput:
    """Test _format_output helper function."""

    def test_none_value(self):
        """Test with None value."""
        assert _format_output(None) == ""

    def test_bytes_value(self):
        """Test with bytes value."""
        assert _format_output(b"test output") == "test output"
        assert _format_output(b"test\noutput") == "test\noutput"

    def test_string_value(self):
        """Test with string value."""
        assert _format_output("test output") == "test output"
        assert _format_output("  test output  ") == "test output"

    def test_other_type(self):
        """Test with other type."""
        assert _format_output(123) == "123"
        assert _format_output(["list"]) == "['list']"


class TestProcessLifecycle:
    """Test ProcessLifecycle functionality."""

    @pytest.fixture
    def mock_watchdog(self):
        """Create a mock watchdog."""
        watchdog = AsyncMock()
        watchdog.start = AsyncMock()
        watchdog.update_activity = AsyncMock()
        return watchdog

    @pytest.fixture
    def mock_registry(self):
        """Create a mock registry."""
        registry = AsyncMock()
        registry.register = AsyncMock()
        registry.get_process = AsyncMock()
        registry.update_status = AsyncMock()
        registry.list_pids = AsyncMock(return_value=[])
        return registry

    @pytest.fixture
    def mock_signal_handler(self):
        """Create a mock signal handler."""
        handler = AsyncMock()
        handler.send = AsyncMock(return_value=True)
        return handler

    @pytest.fixture
    def logger(self):
        """Create a logger."""
        import logging

        return logging.getLogger(__name__)

    @pytest.fixture
    def lifecycle(self, mock_watchdog, mock_registry, mock_signal_handler, logger):
        """Create a ProcessLifecycle instance."""
        return ProcessLifecycle(
            mock_watchdog, mock_registry, mock_signal_handler, logger
        )

    @pytest.mark.asyncio
    async def test_start_process_success(self, lifecycle, mock_watchdog, mock_registry):
        """Test starting a process successfully."""
        config = ProcessConfig(command=["echo", "test"], name="test_process")

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.stderr = AsyncMock()
        mock_process.stdout = AsyncMock()

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            process = await lifecycle.start(config)

            assert process == mock_process
            mock_watchdog.start.assert_called_once()
            mock_watchdog.update_activity.assert_called_once_with(mock_process.pid)
            mock_registry.register.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_process_immediate_exit(self, lifecycle, mock_watchdog):
        """Test starting a process that exits immediately."""
        config = ProcessConfig(command=["false"], name="test_process")

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = 1
        mock_process.stderr = AsyncMock()
        mock_process.stderr.read = AsyncMock(return_value=b"error output")
        mock_process.stdout = AsyncMock()
        mock_process.stdout.read = AsyncMock(return_value=b"")

        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with pytest.raises(ProcessStartError) as exc_info:
                await lifecycle.start(config)

            assert "exited with code 1" in str(exc_info.value)
            assert exc_info.value.context["returncode"] == 1

    @pytest.mark.asyncio
    async def test_start_process_with_cwd(
        self, lifecycle, mock_watchdog, mock_registry
    ):
        """Test starting a process with custom working directory."""
        config = ProcessConfig(command=["pwd"], name="test_process", cwd="/tmp")

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.stderr = AsyncMock()
        mock_process.stdout = AsyncMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_create:
            await lifecycle.start(config)

            # Verify cwd was passed
            call_kwargs = mock_create.call_args[1]
            assert call_kwargs["cwd"] == "/tmp"

    @pytest.mark.asyncio
    async def test_start_process_with_env(
        self, lifecycle, mock_watchdog, mock_registry
    ):
        """Test starting a process with custom environment."""
        config = ProcessConfig(
            command=["env"], name="test_process", env={"TEST_VAR": "test_value"}
        )

        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None
        mock_process.stderr = AsyncMock()
        mock_process.stdout = AsyncMock()

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_create:
            await lifecycle.start(config)

            # Verify env was passed
            call_kwargs = mock_create.call_args[1]
            assert "env" in call_kwargs
            assert call_kwargs["env"]["TEST_VAR"] == "test_value"

    @pytest.mark.asyncio
    async def test_start_process_exception(self, lifecycle, mock_watchdog):
        """Test starting a process that raises an exception."""
        config = ProcessConfig(command=["nonexistent"], name="test_process")

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("Command not found"),
        ):
            with pytest.raises(ProcessStartError) as exc_info:
                await lifecycle.start(config)

            assert "Failed to start process" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_stop_process_not_found(self, lifecycle, mock_registry):
        """Test stopping a process that doesn't exist."""
        mock_registry.get_process.return_value = None

        result = await lifecycle.stop(99999)
        assert result is False

    @pytest.mark.asyncio
    async def test_stop_process_already_exited(
        self, lifecycle, mock_registry, mock_watchdog
    ):
        """Test stopping a process that already exited."""
        mock_process = MagicMock()
        mock_process.returncode = 0

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        result = await lifecycle.stop(12345)
        assert result is True
        mock_registry.update_status.assert_called_once_with(12345, "stopped")

    @pytest.mark.asyncio
    async def test_stop_process_graceful(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Test graceful process termination."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        # Mock wait_for_process_exit to succeed
        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            new_callable=AsyncMock,
        ):
            result = await lifecycle.stop(12345, force=False)

            assert result is True
            mock_signal_handler.send.assert_called_once_with(
                "timeout", 12345, process_info
            )

    @pytest.mark.asyncio
    async def test_stop_process_graceful_timeout_escalation(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Test graceful termination that times out and escalates to force kill."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        # Mock wait_for_process_exit to timeout (graceful), then succeed (force)
        call_count = 0

        async def mock_wait(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise asyncio.TimeoutError()
            # Second call (force kill) succeeds
            mock_process.returncode = 0

        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            side_effect=mock_wait,
        ):
            result = await lifecycle.stop(12345, force=False)

            assert result is True
            # Should call timeout first, then force
            assert mock_signal_handler.send.call_count == 2
            assert mock_signal_handler.send.call_args_list[0][0][0] == "timeout"
            assert mock_signal_handler.send.call_args_list[1][0][0] == "force"

    @pytest.mark.asyncio
    async def test_stop_process_force(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Test force killing a process."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        # Mock wait_for_process_exit to succeed
        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            new_callable=AsyncMock,
        ):
            result = await lifecycle.stop(12345, force=True)

            assert result is True
            mock_signal_handler.send.assert_called_once_with(
                "force", 12345, process_info
            )

    @pytest.mark.asyncio
    async def test_stop_process_force_timeout(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Test force kill that times out."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        # Mock wait_for_process_exit to timeout
        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            side_effect=asyncio.TimeoutError(),
        ):
            # Should still complete (logs warning but continues)
            result = await lifecycle.stop(12345, force=True)
            assert result is True
            mock_signal_handler.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_process_not_exited_mock_process(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Mock process path should return True even when stop is forced."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        # Mock wait_for_process_exit to succeed but process still has None returncode
        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            new_callable=AsyncMock,
        ):
            result = await lifecycle.stop(12345, force=True)
            assert result is True

    @pytest.mark.asyncio
    async def test_stop_process_not_exited_real_process_raises(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Real subprocess-like object should raise if it never exits."""

        class FakeProcess:
            def __init__(self) -> None:
                self.pid = 12345
                self.returncode = None

        fake_process = FakeProcess()
        process_info = {
            "process": fake_process,
            "config": ProcessConfig(command=["test"], name="test_process"),
        }
        mock_registry.get_process.return_value = process_info

        with (
            patch(
                "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
                new_callable=AsyncMock,
            ),
            patch(
                "mcp_fuzzer.fuzz_engine.runtime.lifecycle.asyncio.subprocess.Process",
                FakeProcess,
            ),
        ):
            with pytest.raises(ProcessStopError):
                await lifecycle.stop(12345, force=True)

    @pytest.mark.asyncio
    async def test_stop_all_success(
        self, lifecycle, mock_registry, mock_signal_handler, mock_watchdog
    ):
        """Test stopping all processes successfully."""
        mock_process1 = MagicMock()
        mock_process1.returncode = None
        mock_process2 = MagicMock()
        mock_process2.returncode = None

        process_info1 = {
            "process": mock_process1,
            "config": ProcessConfig(command=["test1"], name="test1"),
        }
        process_info2 = {
            "process": mock_process2,
            "config": ProcessConfig(command=["test2"], name="test2"),
        }

        mock_registry.list_pids.return_value = [11111, 22222]
        mock_registry.get_process.side_effect = [process_info1, process_info2]

        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            new_callable=AsyncMock,
        ):
            await lifecycle.stop_all(force=False)

            assert mock_signal_handler.send.call_count == 2

    @pytest.mark.asyncio
    async def test_stop_all_with_failures(
        self, lifecycle, mock_registry, mock_signal_handler
    ):
        """Test stopping all processes with some failures."""
        mock_process1 = MagicMock()
        mock_process1.returncode = None

        process_info1 = {
            "process": mock_process1,
            "config": ProcessConfig(command=["test1"], name="test1"),
        }

        mock_registry.list_pids.return_value = [11111, 22222]
        mock_registry.get_process.side_effect = [
            process_info1,
            None,  # Second process not found
        ]

        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.lifecycle.wait_for_process_exit",
            new_callable=AsyncMock,
        ):
            with pytest.raises(ProcessStopError) as exc_info:
                await lifecycle.stop_all(force=False)

        assert "Failed to stop all managed processes" in str(exc_info.value)
        assert len(exc_info.value.context["failed_processes"]) == 1

    @pytest.mark.asyncio
    async def test_stop_all_with_exceptions(
        self, lifecycle, mock_registry, mock_signal_handler
    ):
        """Test stopping all processes with exceptions."""
        mock_process = MagicMock()
        mock_process.returncode = None

        process_info = {
            "process": mock_process,
            "config": ProcessConfig(command=["test"], name="test"),
        }

        mock_registry.list_pids.return_value = [11111]
        mock_registry.get_process.return_value = process_info

        # Make signal handler raise an exception
        mock_signal_handler.send.side_effect = Exception("Signal failed")

        with pytest.raises(ProcessStopError) as exc_info:
            await lifecycle.stop_all(force=False)

        assert "Failed to stop all managed processes" in str(exc_info.value)
