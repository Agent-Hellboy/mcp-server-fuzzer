import asyncio
import io
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch, MagicMock, AsyncMock
import signal as _signal
import pytest

# Import the class to test
from mcp_fuzzer.transport.drivers.stdio_driver import StdioDriver
import mcp_fuzzer.transport.drivers.stdio_driver as stdio_driver
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, WatchdogConfig
from mcp_fuzzer.exceptions import (
    ProcessStartError,
    ProcessSignalError,
    ServerError,
    TransportError,
)


class FakeStdin:
    def __init__(self, lines=None, async_mode=False):
        self._lines = list(lines) if lines else []
        self._async = async_mode

    def readline(self):
        if self._async:
            return self._async_readline()
        return self._lines.pop(0) if self._lines else ""

    async def _async_readline(self):
        return self._lines.pop(0) if self._lines else ""


class TestStdioDriver:
    def setup_method(self):
        """Set up test fixtures."""
        self.command = "test_command"
        self.timeout = 10.0
        self.transport = StdioDriver(self.command, self.timeout)
        self.transport.process_manager = AsyncMock(spec=ProcessManager)
        self.transport._lock = AsyncMock(spec=asyncio.Lock)

    def test_init(self):
        """Test initialization of StdioDriver."""
        assert self.transport.command == self.command
        assert self.transport.timeout == self.timeout
        assert self.transport.process is None
        assert self.transport.stdin is None
        assert self.transport.stdout is None
        assert self.transport.stderr is None
        assert self.transport._initialized is False
        assert isinstance(self.transport.process_manager, ProcessManager) or isinstance(
            self.transport.process_manager, AsyncMock
        )

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.transport.drivers.stdio_driver.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.drivers.stdio_driver.shlex.split")
    async def test_ensure_connection_new_process(
        self, mock_shlex_split, mock_create_subprocess
    ):
        """Test _ensure_connection when starting a new process."""
        mock_shlex_split.return_value = ["test_command", "arg1", "arg2"]
        mock_process = AsyncMock()
        mock_process.stdin = AsyncMock()
        mock_process.stdout = AsyncMock()
        mock_process.stderr = AsyncMock()
        mock_process.pid = 12345
        mock_create_subprocess.return_value = mock_process
        self.transport._initialized = False
        self.transport.process = None

        await self.transport._ensure_connection()

        mock_shlex_split.assert_called_once_with(self.command)
        mock_create_subprocess.assert_called_once()
        assert self.transport.process == mock_process
        assert self.transport.stdin == mock_process.stdin
        assert self.transport.stdout == mock_process.stdout
        assert self.transport.stderr == mock_process.stderr
        assert self.transport._initialized is True
        self.transport.process_manager.register_existing_process.assert_called_once_with(
            12345,
            mock_process,
            "stdio_transport",
            self.transport._get_activity_timestamp,
        )

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.transport.drivers.stdio_driver.asyncio.create_subprocess_exec")
    async def test_ensure_connection_existing_process_alive(
        self, mock_create_subprocess
    ):
        """Test _ensure_connection when existing process is alive."""
        mock_process = AsyncMock()
        mock_process.returncode = None
        self.transport.process = mock_process
        self.transport._initialized = True

        await self.transport._ensure_connection()

        mock_create_subprocess.assert_not_called()
        assert self.transport.process == mock_process
        assert self.transport._initialized is True

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.transport.drivers.stdio_driver.asyncio.create_subprocess_exec")
    async def test_ensure_connection_existing_process_dead(
        self, mock_create_subprocess
    ):
        """Test _ensure_connection when existing process is dead."""
        mock_old_process = AsyncMock()
        mock_old_process.returncode = 1
        mock_old_process.pid = 123
        self.transport.process = mock_old_process
        self.transport._initialized = True

        mock_new_process = AsyncMock()
        mock_new_process.stdin = AsyncMock()
        mock_new_process.stdout = AsyncMock()
        mock_new_process.stderr = AsyncMock()
        mock_new_process.pid = 456
        mock_create_subprocess.return_value = mock_new_process

        await self.transport._ensure_connection()

        self.transport.process_manager.stop_process.assert_called_once_with(
            123, force=True
        )
        mock_create_subprocess.assert_called_once()
        assert self.transport.process == mock_new_process
        assert self.transport._initialized is True

    @pytest.mark.asyncio
    async def test_update_activity(self):
        """Test _update_activity method."""
        with patch("time.time", return_value=1234567890.0):
            self.transport.process = AsyncMock()
            self.transport.process.pid = 123
            # Mock the process_manager.update_activity method to avoid AsyncMock issues
            with patch.object(
                self.transport.process_manager, "update_activity", AsyncMock()
            ):
                await self.transport._update_activity()
                assert self.transport._last_activity == 1234567890.0

    @pytest.mark.asyncio
    async def test_get_activity_timestamp(self):
        """Test _get_activity_timestamp method."""
        self.transport._last_activity = 1234567890.0
        assert self.transport._get_activity_timestamp() == 1234567890.0

    @pytest.mark.asyncio
    async def test_send_message(self):
        """Test _send_message method."""
        self.transport._initialized = True
        self.transport.stdin = AsyncMock()
        message = {"test": "data"}
        with patch.object(self.transport, "_update_activity") as mock_update:
            await self.transport._send_message(message)
            self.transport.stdin.write.assert_called_once_with(
                json.dumps(message).encode() + b"\n"
            )
            self.transport.stdin.drain.assert_awaited_once()
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_message_not_initialized(self):
        """Test _send_message when not initialized."""
        self.transport._initialized = False
        # We need to mock stdin to prevent NoneType error
        mock_stdin = MagicMock()
        mock_stdin.drain = AsyncMock()
        self.transport.stdin = mock_stdin

        with patch.object(
            self.transport, "_ensure_connection", new=AsyncMock()
        ) as mock_ensure:
            await self.transport._send_message({"test": "data"})
            mock_ensure.assert_awaited_once()
            # Verify stdin.write and drain were called
            mock_stdin.write.assert_called_once()
            mock_stdin.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message(self):
        """Test _receive_message method."""
        self.transport._initialized = True
        self.transport.stdout = AsyncMock()
        self.transport.manager.read_with_cap = AsyncMock(
            return_value=b'{"response": "ok"}\n'
        )
        with patch.object(self.transport, "_update_activity") as mock_update:
            result = await self.transport._receive_message()
            assert result == {"response": "ok"}
            self.transport.manager.read_with_cap.assert_awaited_once()
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_receive_message_empty_response(self):
        """Test _receive_message when empty response is received."""
        self.transport._initialized = True
        self.transport.stdout = AsyncMock()
        self.transport.manager.read_with_cap = AsyncMock(return_value=b"")
        result = await self.transport._receive_message()
        assert result is None
        self.transport.manager.read_with_cap.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message_not_initialized(self):
        """Test _receive_message when not initialized."""
        self.transport._initialized = False
        # We need to mock stdout to prevent NoneType error
        self.transport.stdout = AsyncMock()
        self.transport.manager.read_with_cap = AsyncMock(
            return_value=b'{"response": "ok"}\n'
        )

        with patch.object(
            self.transport, "_ensure_connection", new=AsyncMock()
        ) as mock_ensure:
            result = await self.transport._receive_message()
            mock_ensure.assert_awaited_once()
            assert result == {"response": "ok"}

    @pytest.mark.asyncio
    async def test_send_request(self):
        """Test send_request method."""
        with (
            patch.object(self.transport, "_send_message", new=AsyncMock()) as mock_send,
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.uuid.uuid4"
            ) as mock_uuid4,
            patch.object(
                self.transport,
                "_receive_message",
                new=AsyncMock(
                    return_value={"id": "req-id", "result": {"ok": True}}
                ),
            ),
        ):
            mock_uuid4.return_value = "req-id"
            result = await self.transport.send_request("method", {"x": 1})

        assert result == {"ok": True}
        sent_message = mock_send.call_args_list[0][0][0]
        assert sent_message["id"] == "req-id"
        assert sent_message["method"] == "method"

    @pytest.mark.asyncio
    async def test_send_request_handles_sampling_request(self):
        """send_request should reply to sampling/createMessage requests."""
        server_request = {
            "jsonrpc": "2.0",
            "id": "srv-id",
            "method": "sampling/createMessage",
            "params": {"messages": [], "maxTokens": 1},
        }
        response = {"id": "req-id", "result": {"ok": True}}
        with (
            patch.object(self.transport, "_send_message", new=AsyncMock()) as mock_send,
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.uuid.uuid4"
            ) as mock_uuid4,
            patch.object(
                self.transport,
                "_receive_message",
                new=AsyncMock(side_effect=[server_request, response]),
            ),
        ):
            mock_uuid4.return_value = "req-id"
            result = await self.transport.send_request("method", {"x": 1})

        assert result == {"ok": True}
        assert mock_send.call_count == 2
        sampling_reply = mock_send.call_args_list[1][0][0]
        assert sampling_reply["id"] == "srv-id"
        assert sampling_reply["result"]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_send_request_error_response(self):
        """Test send_request method with error response."""
        with (
            patch.object(self.transport, "_send_message", new=AsyncMock()),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.uuid.uuid4"
            ) as mock_uuid4,
            patch.object(
                self.transport,
                "_receive_message",
                new=AsyncMock(
                    return_value={"id": "req-id", "error": {"code": -1}}
                ),
            ),
        ):
            mock_uuid4.return_value = "req-id"
            with pytest.raises(ServerError):
                await self.transport.send_request("method", {"x": 1})

    @pytest.mark.asyncio
    async def test_send_request_no_response(self):
        """send_request should raise TransportError when no response arrives."""
        with (
            patch.object(self.transport, "_send_message", new=AsyncMock()),
            patch("mcp_fuzzer.transport.drivers.stdio_driver.uuid") as mock_uuid,
            patch.object(
                self.transport, "_receive_message", new=AsyncMock(return_value=None)
            ),
        ):
            mock_uuid.uuid4.return_value = "test_id"
            with pytest.raises(TransportError):
                await self.transport.send_request("method", {})

    @pytest.mark.asyncio
    async def test_send_raw(self):
        """Test send_raw method."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            with patch.object(
                self.transport, "_receive_message", new=AsyncMock()
            ) as mock_receive:
                # Simple return value
                mock_receive.return_value = {"result": {"success": True}}

                result = await self.transport.send_raw({"raw": "data"})

                assert result == {"success": True}
                mock_send.assert_awaited_once_with({"raw": "data"})
                mock_receive.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_raw_handles_sampling_request(self):
        """send_raw should reply to sampling/createMessage requests."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            server_request = {
                "jsonrpc": "2.0",
                "id": "srv-id",
                "method": "sampling/createMessage",
                "params": {"messages": [], "maxTokens": 1},
            }
            response = {"result": {"ok": True}}
            with patch.object(
                self.transport,
                "_receive_message",
                new=AsyncMock(side_effect=[server_request, response]),
            ):
                result = await self.transport.send_raw({"raw": "data"})

            assert result == {"ok": True}
            assert mock_send.call_count == 2
            sampling_reply = mock_send.call_args_list[1][0][0]
            assert sampling_reply["id"] == "srv-id"
            assert sampling_reply["result"]["role"] == "assistant"

    @pytest.mark.asyncio
    async def test_send_raw_error_response(self):
        """Test send_raw method with error response."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            with patch.object(
                self.transport, "_receive_message", new=AsyncMock()
            ) as mock_receive:
                mock_receive.return_value = {
                    "error": {"code": -1, "message": "Test error"}
                }

                # Use pytest's raises context manager
                with pytest.raises(ServerError):
                    await self.transport.send_raw({"raw": "data"})
                mock_send.assert_awaited_once()
                mock_receive.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_notification(self):
        """Test send_notification method."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            await self.transport.send_notification("test_method", {"param": "value"})
            mock_send.assert_awaited_once()
            call_args = mock_send.call_args[0][0]
            assert call_args["method"] == "test_method"
            assert call_args["params"] == {"param": "value"}
            assert "id" not in call_args

    @pytest.mark.asyncio
    async def test_close_with_process(self):
        """Test close method with an active process."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport._initialized = True

        with patch("asyncio.wait_for", new=AsyncMock()) as mock_wait_for:
            await self.transport.close()
            self.transport.process_manager.stop_process.assert_awaited_once_with(
                123, force=True
            )
            mock_wait_for.assert_awaited_once()
            assert self.transport._initialized is False
            assert self.transport.process is None
            assert self.transport.stdin is None
            assert self.transport.stdout is None
            assert self.transport.stderr is None

    @pytest.mark.asyncio
    async def test_close_without_process(self):
        """Test close method without an active process."""
        self.transport.process = None
        self.transport._initialized = True

        await self.transport.close()
        self.transport.process_manager.stop_process.assert_not_awaited()
        assert self.transport._initialized is False
        assert self.transport.process is None
        assert self.transport.stdin is None
        assert self.transport.stdout is None
        assert self.transport.stderr is None

    @pytest.mark.asyncio
    async def test_get_process_stats(self):
        """Test get_process_stats method."""
        mock_stats = {"active_processes": 1}
        self.transport.process_manager.get_stats.return_value = mock_stats
        result = await self.transport.get_process_stats()
        assert result == mock_stats
        self.transport.process_manager.get_stats.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_registered(self):
        """Test send_timeout_signal when process is registered with manager."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = True
        self.transport.process_manager.send_timeout_signal.return_value = True

        result = await self.transport.send_timeout_signal("timeout")
        assert result is True
        self.transport.process_manager.is_process_registered.assert_awaited_once_with(
            123
        )
        self.transport.process_manager.send_timeout_signal.assert_awaited_once_with(
            123, "timeout"
        )

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_registered_timeout(self):
        """Test send_timeout_signal when process is not registered,
        sending timeout signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with (
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.name",
                "posix",
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.getpgid",
                return_value=999,
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.killpg"
            ) as mock_killpg,
        ):
            result = await self.transport.send_timeout_signal("timeout")

        assert result is True
        mock_killpg.assert_called_once_with(999, _signal.SIGTERM)

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_registered_force(self):
        """Test send_timeout_signal when process is not registered,
        sending force signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with (
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.name",
                "posix",
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.getpgid",
                return_value=999,
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.killpg"
            ) as mock_killpg,
        ):
            result = await self.transport.send_timeout_signal("force")

        assert result is True
        mock_killpg.assert_called_once_with(999, _signal.SIGKILL)

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_registered_interrupt(self):
        """Test send_timeout_signal when process is not registered,
        sending interrupt signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with (
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.name",
                "posix",
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.getpgid",
                return_value=999,
            ),
            patch(
                "mcp_fuzzer.transport.drivers.stdio_driver.os.killpg"
            ) as mock_killpg,
        ):
            result = await self.transport.send_timeout_signal("interrupt")

        assert result is True
        mock_killpg.assert_called_once_with(999, _signal.SIGINT)

    @pytest.mark.skip(
        reason="Test isolation issue: send_timeout_signal requires complex mocking of "
        "OS-level operations (os.getpgid, os.killpg) that can be affected by test "
        "execution order. This functionality is better covered by integration tests."
    )
    @pytest.mark.asyncio
    async def _test_send_timeout_signal_process_not_registered_interrupt_old(self):
        """Test send_timeout_signal when process is not registered,
        sending interrupt signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with patch(
            "mcp_fuzzer.transport.drivers.stdio_driver.logging.info"
        ) as mock_log:
            with patch("mcp_fuzzer.transport.drivers.stdio_driver.os") as mock_os:
                # Mock kill to avoid OS errors
                mock_os.name = "posix"

                result = await self.transport.send_timeout_signal("interrupt")

                # For interrupt signal with non-registered process, uses killpg+SIGINT
                mock_os.killpg.assert_called_once()
                mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal_unknown_signal_type(self):
        """Test send_timeout_signal with unknown signal type."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        result = await self.transport.send_timeout_signal("unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_timeout_signal_no_process(self):
        """Test send_timeout_signal when no process exists."""
        self.transport.process = None
        result = await self.transport.send_timeout_signal("timeout")
        assert result is False

    @pytest.mark.asyncio
    async def test_send_raw_no_response(self):
        """send_raw should raise TransportError when no message arrives."""
        with (
            patch.object(self.transport, "_send_message", new=AsyncMock()),
            patch.object(
                self.transport, "_receive_message", new=AsyncMock(return_value=None)
            ),
        ):
            with pytest.raises(TransportError):
                await self.transport.send_raw({"raw": "data"})

    def test_get_lock_lazy_initialization(self):
        """Test _get_lock creates lock lazily."""
        transport = StdioDriver("test_command")
        assert transport._lock is None
        lock1 = transport._get_lock()
        assert transport._lock is not None
        assert isinstance(lock1, asyncio.Lock)
        # Second call should return same lock
        lock2 = transport._get_lock()
        assert lock1 is lock2

    def test_add_observer(self):
        """Test add_observer method."""
        callback = MagicMock()
        # Mock the manager's add_observer method
        with patch.object(self.transport.manager, "add_observer") as mock_add:
            self.transport.add_observer(callback)
            # Verify observer was added to manager
            mock_add.assert_called_once_with(callback)

    def test_get_process_manager_lazy_initialization(self):
        """Test _get_process_manager creates manager lazily."""
        transport = StdioDriver("test_command", timeout=15.0)
        assert transport.process_manager is None
        manager = transport._get_process_manager()
        assert transport.process_manager is not None
        assert isinstance(manager, ProcessManager)
        # Second call should return same manager
        manager2 = transport._get_process_manager()
        assert manager is manager2

    @pytest.mark.asyncio
    async def test_ensure_connection_early_return_when_initialized(self):
        """Test _ensure_connection returns early when already initialized."""
        mock_process = AsyncMock()
        mock_process.returncode = None
        mock_process.pid = 12345
        self.transport.process = mock_process
        self.transport._initialized = True

        with patch(
            "mcp_fuzzer.transport.drivers.stdio_driver.asyncio.create_subprocess_exec",
            new=AsyncMock(),
        ) as mock_create:
            # Should return immediately without locking
            await self.transport._ensure_connection()
            mock_create.assert_not_called()

    @pytest.mark.skipif(
        sys.platform != "win32",
        reason="Windows-specific test: requires Windows subprocess constants",
    )
    @pytest.mark.asyncio
    async def test_ensure_connection_fallback_termination_windows(self):
        """Test fallback process termination on Windows."""
        mock_process = MagicMock(spec=["send_signal", "kill"])
        self.transport.process = mock_process
        self.transport._initialized = True
        self.transport.process_manager.stop_process = AsyncMock()

        with patch("mcp_fuzzer.transport.drivers.stdio_driver._signal") as mock_signal:
            mock_signal.CTRL_BREAK_EVENT = 1
            with patch.object(
                mock_process, "send_signal", side_effect=AttributeError()
            ):
                with patch.object(mock_process, "kill") as mock_kill:
                    # Need to mock the lock and other dependencies
                    self.transport._lock = AsyncMock()
                    mock_new_process = AsyncMock()
                    mock_new_process.pid = 12345
                    mock_new_process.stdin = AsyncMock()
                    mock_new_process.stdout = AsyncMock()
                    mock_new_process.stderr = AsyncMock()
                    mock_new_process.returncode = None
                    with patch(
                        "asyncio.create_subprocess_exec",
                        return_value=mock_new_process,
                    ):
                        await self.transport._ensure_connection()
                        mock_kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_connection_stop_process_exception_handling(self):
        """Test _ensure_connection handles stop_process exceptions gracefully."""
        mock_process = MagicMock()
        mock_process.pid = 12345
        self.transport.process = mock_process
        self.transport._initialized = True
        # Make process manager fail - exception will be caught and logged
        self.transport.process_manager.stop_process = AsyncMock(
            side_effect=Exception("Manager failed")
        )

        with patch("sys.platform", "linux"):
            with patch.object(mock_process, "kill") as mock_kill:
                # Need to mock the lock and other dependencies
                self.transport._lock = AsyncMock()
                mock_new_process = AsyncMock()
                mock_new_process.pid = 12345
                mock_new_process.stdin = AsyncMock()
                mock_new_process.stdout = AsyncMock()
                mock_new_process.stderr = AsyncMock()
                mock_new_process.returncode = None
                with patch(
                    "asyncio.create_subprocess_exec", return_value=mock_new_process
                ):
                    # Process manager fails, exception is caught, code continues
                    await self.transport._ensure_connection()
                    # Process manager was called
                    self.transport.process_manager.stop_process.assert_awaited_once()
                    # But kill is not called because exception was caught
                    mock_kill.assert_not_called()

    @pytest.mark.asyncio
    async def test_ensure_connection_command_as_list(self):
        """Test _ensure_connection with command as list instead of string."""
        transport = StdioDriver(["python", "-c", "print('test')"])
        transport.process_manager = AsyncMock(spec=ProcessManager)
        transport._lock = AsyncMock(spec=asyncio.Lock)

        mock_process = AsyncMock()
        mock_process.stdin = AsyncMock()
        mock_process.stdout = AsyncMock()
        mock_process.stderr = AsyncMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        with patch(
            "asyncio.create_subprocess_exec", return_value=mock_process
        ) as mock_create:
            await transport._ensure_connection()
            # Should pass command list directly without shlex.split
            mock_create.assert_called_once()
            call_args = mock_create.call_args[0]
            assert call_args[0:3] == ("python", "-c", "print('test')")

    @pytest.mark.asyncio
    async def test_ensure_connection_process_start_exception(self):
        """Test _ensure_connection handles process start exceptions."""
        transport = StdioDriver("nonexistent_command")
        transport.process_manager = AsyncMock(spec=ProcessManager)
        transport._lock = AsyncMock(spec=asyncio.Lock)

        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("Command not found"),
        ):
            with pytest.raises(ProcessStartError):
                await transport._ensure_connection()
            assert transport._initialized is False

    @pytest.mark.asyncio
    async def test_send_message_exception_handling(self):
        """Test _send_message handles exceptions."""
        self.transport._initialized = True
        self.transport.stdin = AsyncMock()
        self.transport.stdin.write = MagicMock(side_effect=OSError("Write failed"))

        with pytest.raises(TransportError):
            await self.transport._send_message({"test": "message"})

        assert self.transport._initialized is False

    @pytest.mark.asyncio
    async def test_handle_server_request_non_matching_method(self):
        """Test _handle_server_request with non-matching method."""
        message = {"jsonrpc": "2.0", "method": "other/method", "id": 1}
        result = await self.transport._handle_server_request(message)
        assert result is False

    @pytest.mark.asyncio
    async def test_readline_with_cap_no_stdout(self):
        """Test _readline_with_cap when stdout is None."""
        self.transport.stdout = None
        result = await self.transport._readline_with_cap()
        assert result is None



class TestStdioDriverExtended:
    @pytest.mark.asyncio
    async def test_handle_server_request_sampling_create_message(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._send_message = AsyncMock()
    
        payload = {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage"}
        handled = await transport._handle_server_request(payload)
    
        assert handled is True
        transport._send_message.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_receive_message_error_resets_state(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport.manager = SimpleNamespace(state=MagicMock())
        transport._readline_with_cap = AsyncMock(side_effect=ValueError("boom"))
    
        with pytest.raises(TransportError):
            await transport._receive_message()
    
        assert transport._initialized is False
    
    
    @pytest.mark.asyncio
    async def test_send_request_no_response_module(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport._send_message = AsyncMock()
        transport._receive_message = AsyncMock(return_value=None)
    
        with pytest.raises(TransportError):
            await transport.send_request("ping")
    
    
    @pytest.mark.asyncio
    async def test_send_request_server_error(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport._send_message = AsyncMock()
        monkeypatch.setattr(stdio_driver.uuid, "uuid4", lambda: "req")
        transport._receive_message = AsyncMock(
            return_value={"id": "req", "error": {"code": -1, "message": "bad"}}
        )
    
        with pytest.raises(ServerError):
            await transport.send_request("ping")
    
    
    @pytest.mark.asyncio
    async def test_send_request_initialize_updates_spec(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport._send_message = AsyncMock()
    
        monkeypatch.setattr(stdio_driver.uuid, "uuid4", lambda: "req")
        transport._receive_message = AsyncMock(
            return_value={"id": "req", "result": {"protocolVersion": "2025-11-25"}}
        )
    
        seen = {}
        monkeypatch.setattr(
            stdio_driver,
            "maybe_update_spec_version_from_result",
            lambda result: seen.setdefault("pv", result.get("protocolVersion")),
        )
    
        result = await transport.send_request("initialize")
        assert result["protocolVersion"] == "2025-11-25"
        assert seen["pv"] == "2025-11-25"
    
    
    @pytest.mark.asyncio
    async def test_send_request_exhausts_iterations(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport._send_message = AsyncMock()
        transport._receive_message = AsyncMock(return_value={"id": "other"})
    
        with pytest.raises(TransportError):
            await transport.send_request("ping")
    
    
    @pytest.mark.asyncio
    async def test_send_raw_initialize_updates_spec(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport._send_message = AsyncMock()
        transport._receive_message = AsyncMock(
            return_value={"result": {"protocolVersion": "2025-11-25"}}
        )
    
        seen = {}
        monkeypatch.setattr(
            stdio_driver,
            "maybe_update_spec_version_from_result",
            lambda result: seen.setdefault("pv", result.get("protocolVersion")),
        )
    
        result = await transport.send_raw({"method": "initialize"})
    
        assert result["protocolVersion"] == "2025-11-25"
        assert seen["pv"] == "2025-11-25"
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_unknown_direct(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(pid=123)
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(
            is_process_registered=AsyncMock(return_value=False),
        )
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        assert await transport.send_timeout_signal("unknown") is False
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_registered(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(pid=123)
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(
            is_process_registered=AsyncMock(return_value=True),
            send_timeout_signal=AsyncMock(return_value=True),
        )
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        assert await transport.send_timeout_signal("timeout") is True
    
    
    @pytest.mark.asyncio
    async def test_ensure_connection_fallback_kill(self, monkeypatch):
        transport = StdioDriver("echo")
        transport._initialized = True
        transport.manager = SimpleNamespace(
            state=MagicMock(),
            emit_event=MagicMock(),
            apply_backoff=AsyncMock(return_value=0.0),
            restart_attempts=1,
            reset_backoff=MagicMock(),
        )
    
        class DeadProc:
            def __init__(self):
                self.returncode = 1
                self.kill = MagicMock()
    
            def send_signal(self, _sig):
                raise AttributeError("no signal")
    
        old_proc = DeadProc()
        transport.process = old_proc
        monkeypatch.setattr(stdio_driver.sys, "platform", "win32")
        monkeypatch.setattr(
            stdio_driver.subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0,
            raising=False,
        )
    
        pm = SimpleNamespace(
            stop_process=AsyncMock(),
            register_existing_process=AsyncMock(),
            update_activity=AsyncMock(),
        )
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        class NewProc:
            def __init__(self):
                self.pid = 123
                self.stdin = AsyncMock()
                self.stdout = AsyncMock()
                self.stderr = AsyncMock()
                self.returncode = None
    
        async def _create_proc(*_args, **_kwargs):
            return NewProc()
    
        monkeypatch.setattr(
            stdio_driver.asyncio,
            "create_subprocess_exec",
            _create_proc,
        )
    
        await transport._ensure_connection()
        old_proc.kill.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_send_request_reads_json(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.request_id = 7

        stdout = io.StringIO()
        stdin = FakeStdin([b'{"jsonrpc": "2.0", "id": 7, "result": 3}'])
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        result = await transport._send_request({"method": "ping"})
        assert result["result"] == 3
    
    
    @pytest.mark.asyncio
    async def test_send_request_no_line(self, monkeypatch):
        transport = StdioDriver("echo")

        stdout = io.StringIO()
        stdin = FakeStdin()
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        with pytest.raises(TransportError):
            await transport._send_request({"method": "ping"})
    
    
    @pytest.mark.asyncio
    async def test_send_request_awaitable_line(self, monkeypatch):
        transport = StdioDriver("echo")

        stdout = io.StringIO()
        stdin = FakeStdin(
            ['{"jsonrpc": "2.0", "id": 1, "result": "ok"}'],
            async_mode=True,
        )
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        result = await transport._send_request({"method": "ping"})
        assert result["result"] == "ok"
    
    
    @pytest.mark.asyncio
    async def test_stream_request_skips_invalid_json(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.request_id = 2

        stdout = io.StringIO()
        stdin = FakeStdin(['{bad json}', '{"ok": 1}', ""])
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        items = []
        async for item in transport._stream_request({"method": "stream"}):
            items.append(item)
        assert items == [{"ok": 1}]
    
    
    @pytest.mark.asyncio
    async def test_stream_request_bytes(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.request_id = 3

        stdout = io.StringIO()
        stdin = FakeStdin([b'{"ok": 2}', b""])
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        items = []
        async for item in transport._stream_request({"method": "stream"}):
            items.append(item)
        assert items == [{"ok": 2}]
    
    
    @pytest.mark.asyncio
    async def test_stream_request_awaitable_line(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.request_id = 4

        stdout = io.StringIO()
        stdin = FakeStdin(['{"ok": 4}', ""], async_mode=True)
        monkeypatch.setattr(
            stdio_driver,
            "sys",
            SimpleNamespace(stdin=stdin, stdout=stdout),
        )
    
        items = []
        async for item in transport._stream_request({"method": "stream"}):
            items.append(item)
            break
        assert items == [{"ok": 4}]
    
    
    @pytest.mark.asyncio
    async def test_close_registers_and_waits(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(pid=123, wait=AsyncMock())
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(
            is_process_registered=AsyncMock(return_value=False),
            register_existing_process=AsyncMock(),
            stop_process=AsyncMock(),
        )
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        async def _raise_wait(*_args, **_kwargs):
            raise asyncio.TimeoutError()
    
        monkeypatch.setattr(stdio_driver.asyncio, "wait_for", _raise_wait)
    
        await transport.close()
        pm.register_existing_process.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_close_fallback_without_pid(self, monkeypatch):
        transport = StdioDriver("echo")
        proc = SimpleNamespace(
            send_signal=MagicMock(),
            kill=MagicMock(),
        )
        transport.process = proc
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
        monkeypatch.setattr(stdio_driver.sys, "platform", "win32")
    
        await transport.close()
        proc.kill.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_timeout_direct(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(
            pid=321,
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(is_process_registered=AsyncMock(return_value=False))
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        def _raise_oserror(*_args, **_kwargs):
            raise OSError()
    
        monkeypatch.setattr(stdio_driver.os, "getpgid", _raise_oserror)
    
        assert await transport.send_timeout_signal("timeout") is True
        transport.process.terminate.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_force_direct(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(
            pid=321,
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(is_process_registered=AsyncMock(return_value=False))
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        def _raise_oserror(*_args, **_kwargs):
            raise OSError()
    
        monkeypatch.setattr(stdio_driver.os, "getpgid", _raise_oserror)
    
        assert await transport.send_timeout_signal("force") is True
        transport.process.kill.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_interrupt_direct(self, monkeypatch):
        transport = StdioDriver("echo")
        transport.process = SimpleNamespace(
            pid=321,
            terminate=MagicMock(),
            kill=MagicMock(),
        )
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(is_process_registered=AsyncMock(return_value=False))
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        def _raise_oserror(*_args, **_kwargs):
            raise OSError()
    
        monkeypatch.setattr(stdio_driver.os, "getpgid", _raise_oserror)
    
        assert await transport.send_timeout_signal("interrupt") is True
        transport.process.terminate.assert_called_once()
    
    
    @pytest.mark.asyncio
    async def test_send_timeout_signal_direct_failure(self, monkeypatch):
        transport = StdioDriver("echo")
    
        def _boom(*_args, **_kwargs):
            raise RuntimeError("boom")
    
        transport.process = SimpleNamespace(pid=321, terminate=_boom, kill=_boom)
        transport.manager = SimpleNamespace(state=MagicMock(), emit_event=MagicMock())
    
        pm = SimpleNamespace(is_process_registered=AsyncMock(return_value=False))
        monkeypatch.setattr(transport, "_get_process_manager", lambda: pm)
    
        def _raise_oserror(*_args, **_kwargs):
            raise OSError()
    
        monkeypatch.setattr(stdio_driver.os, "getpgid", _raise_oserror)
    
        with pytest.raises(ProcessSignalError):
            await transport.send_timeout_signal("timeout")
