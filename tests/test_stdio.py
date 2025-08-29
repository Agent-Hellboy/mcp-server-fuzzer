import asyncio
import json
import os
import sys
from unittest.mock import patch, MagicMock, AsyncMock
import signal as _signal
import pytest

# Import the class to test
from mcp_fuzzer.transport.stdio import StdioTransport
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, WatchdogConfig
from mcp_fuzzer.exceptions import MCPError


class TestStdioTransport:
    def setup_method(self):
        """Set up test fixtures."""
        self.command = "test_command"
        self.timeout = 10.0
        self.transport = StdioTransport(self.command, self.timeout)
        self.transport.process_manager = AsyncMock(spec=ProcessManager)
        self.transport._lock = AsyncMock(spec=asyncio.Lock)

    def test_init(self):
        """Test initialization of StdioTransport."""
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
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
    @patch("mcp_fuzzer.transport.stdio.shlex.split")
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
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
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
    @patch("mcp_fuzzer.transport.stdio.asyncio.create_subprocess_exec")
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
        self.transport.stdout.readline.return_value = b'{"response": "ok"}\n'
        with patch.object(self.transport, "_update_activity") as mock_update:
            result = await self.transport._receive_message()
            assert result == {"response": "ok"}
            self.transport.stdout.readline.assert_awaited_once()
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_receive_message_empty_response(self):
        """Test _receive_message when empty response is received."""
        self.transport._initialized = True
        self.transport.stdout = AsyncMock()
        self.transport.stdout.readline.return_value = b""
        result = await self.transport._receive_message()
        assert result is None
        self.transport.stdout.readline.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message_not_initialized(self):
        """Test _receive_message when not initialized."""
        self.transport._initialized = False
        # We need to mock stdout to prevent NoneType error
        mock_stdout = AsyncMock()
        mock_stdout.readline = AsyncMock(return_value=b'{"response": "ok"}\n')
        self.transport.stdout = mock_stdout

        with patch.object(
            self.transport, "_ensure_connection", new=AsyncMock()
        ) as mock_ensure:
            result = await self.transport._receive_message()
            mock_ensure.assert_awaited_once()
            assert result == {"response": "ok"}

    @pytest.mark.asyncio
    async def test_send_request(self):
        """Test send_request method."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            with patch("mcp_fuzzer.transport.stdio.uuid") as mock_uuid:
                # Force the request_id to a known value
                mock_uuid.uuid4.return_value = "test_id"

                with patch.object(
                    self.transport, "_receive_message", new=AsyncMock()
                ) as mock_receive:
                    # Set up a return value that matches the request ID we defined
                    mock_receive.return_value = {
                        "id": "test_id",
                        "result": {"success": True},
                    }

                    result = await self.transport.send_request(
                        "test_method", {"param": "value"}
                    )

                    assert result == {"success": True}
                    mock_send.assert_awaited_once()
                    assert mock_receive.call_count == 1

    @pytest.mark.asyncio
    async def test_send_request_error_response(self):
        """Test send_request method with error response."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ) as mock_send:
            with patch("mcp_fuzzer.transport.stdio.uuid") as mock_uuid:
                # Force the request_id to a known value
                mock_uuid.uuid4.return_value = "test_id"

                with patch.object(
                    self.transport, "_receive_message", new=AsyncMock()
                ) as mock_receive:
                    mock_receive.return_value = {
                        "id": "test_id",
                        "error": {"code": -1, "message": "Test error"},
                    }

                    # Use pytest's raises context manager
                    with pytest.raises(Exception, match="Server error") as excinfo:
                        await self.transport.send_request(
                            "test_method", {"param": "value"}
                        )

                    mock_send.assert_awaited_once()
                    mock_receive.assert_awaited_once()

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
                with pytest.raises(Exception) as excinfo:
                    await self.transport.send_raw({"raw": "data"})

                assert "Test error" in str(excinfo.value)
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

        with patch("mcp_fuzzer.transport.stdio.logging.info") as mock_log:
            with patch("mcp_fuzzer.transport.stdio.os") as mock_os:
                # Mock getpgid to avoid OS errors
                mock_os.name = "posix"
                mock_os.getpgid.return_value = 123

                result = await self.transport.send_timeout_signal("timeout")

                # For timeout signal with non-registered process, should use killpg
                mock_os.killpg.assert_called_once()
                mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_registered_force(self):
        """Test send_timeout_signal when process is not registered,
        sending force signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with patch("mcp_fuzzer.transport.stdio.logging.info") as mock_log:
            with patch("mcp_fuzzer.transport.stdio.os") as mock_os:
                # Mock kill to avoid OS errors
                mock_os.name = "posix"

                result = await self.transport.send_timeout_signal("force")

                # For force signal with non-registered process, uses killpg+SIGKILL
                mock_os.killpg.assert_called_once()
                mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout_signal_process_not_registered_interrupt(self):
        """Test send_timeout_signal when process is not registered,
        sending interrupt signal."""
        mock_process = MagicMock()
        mock_process.pid = 123
        self.transport.process = mock_process
        self.transport.process_manager.is_process_registered.return_value = False

        with patch("mcp_fuzzer.transport.stdio.logging.info") as mock_log:
            with patch("mcp_fuzzer.transport.stdio.os") as mock_os:
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
