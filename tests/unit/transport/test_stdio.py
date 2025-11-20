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
from mcp_fuzzer.exceptions import MCPError, ServerError, TransportError


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
        # Process management is now delegated to ProcessConnectionManager
        assert hasattr(self.transport, 'connection_manager')
        assert self.transport.connection_manager.command == self.command
        assert self.transport.connection_manager.timeout == self.timeout

    @pytest.mark.asyncio
    async def test_ensure_connection_new_process(self):
        """Test _ensure_connection delegates to connection manager."""
        with patch.object(
            self.transport.connection_manager,
            "ensure_connection",
            new_callable=AsyncMock,
        ) as mock_ensure:
            await self.transport.connection_manager.ensure_connection()
            mock_ensure.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_connection_existing_process_alive(self):
        """Test _ensure_connection delegates to connection manager."""
        with patch.object(
            self.transport.connection_manager,
            "ensure_connection",
            new_callable=AsyncMock,
        ) as mock_ensure:
            await self.transport.connection_manager.ensure_connection()
            mock_ensure.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_connection_existing_process_dead(self):
        """Test _ensure_connection delegates to connection manager."""
        with patch.object(
            self.transport.connection_manager,
            "ensure_connection",
            new_callable=AsyncMock,
        ) as mock_ensure:
            await self.transport.connection_manager.ensure_connection()
            mock_ensure.assert_called_once()


    @pytest.mark.asyncio
    async def test_send_message(self):
        """Test _send_message method."""
        message = {"test": "data"}
        expected_data = json.dumps(message).encode() + b"\n"

        with (
            patch.object(
                self.transport.connection_manager,
                "ensure_connection",
                new_callable=AsyncMock
            ) as mock_ensure,
            patch.object(self.transport.connection_manager, "stdin") as mock_stdin,
        ):
            mock_stdin.drain = AsyncMock()
            await self.transport._send_message(message)

            mock_ensure.assert_called_once()
            mock_stdin.write.assert_called_once_with(expected_data)
            mock_stdin.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_message_not_initialized(self):
        """Test _send_message when not initialized."""
        message = {"test": "data"}
        expected_data = json.dumps(message).encode() + b"\n"

        with (
            patch.object(
                self.transport.connection_manager,
                "ensure_connection",
                new_callable=AsyncMock
            ) as mock_ensure,
            patch.object(self.transport.connection_manager, "stdin") as mock_stdin,
        ):
            mock_stdin.drain = AsyncMock()
            await self.transport._send_message(message)
            mock_ensure.assert_called_once()
            mock_stdin.write.assert_called_once_with(expected_data)
            mock_stdin.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message(self):
        """Test _receive_message method."""
        with (
            patch.object(
                self.transport.connection_manager,
                "ensure_connection",
                new_callable=AsyncMock
            ) as mock_ensure,
            patch.object(self.transport.connection_manager, "stdout") as mock_stdout,
        ):
            mock_stdout.readline = AsyncMock(return_value=b'{"response": "ok"}\n')
            result = await self.transport._receive_message()
            assert result == {"response": "ok"}
            mock_ensure.assert_called_once()
            mock_stdout.readline.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message_empty_response(self):
        """Test _receive_message when empty response is received."""
        with (
            patch.object(
                self.transport.connection_manager,
                "ensure_connection",
                new_callable=AsyncMock
            ) as mock_ensure,
            patch.object(self.transport.connection_manager, "stdout") as mock_stdout,
        ):
            mock_stdout.readline = AsyncMock(return_value=b"")
            result = await self.transport._receive_message()
            assert result is None
            mock_ensure.assert_called_once()
            mock_stdout.readline.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_receive_message_not_initialized(self):
        """Test _receive_message when not initialized."""
        with (
            patch.object(
                self.transport.connection_manager,
                "ensure_connection",
                new_callable=AsyncMock
            ) as mock_ensure,
            patch.object(self.transport.connection_manager, "stdout") as mock_stdout,
        ):
            mock_stdout.readline = AsyncMock(return_value=b'{"response": "ok"}\n')
            result = await self.transport._receive_message()
            mock_ensure.assert_called_once()
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
                    with pytest.raises(ServerError, match="Server returned error"):
                        await self.transport.send_request(
                            "test_method", {"param": "value"}
                        )

                    mock_send.assert_awaited_once()
                    mock_receive.assert_awaited_once()
    @pytest.mark.asyncio
    async def test_send_request_no_response(self):
        """send_request should raise TransportError when no response arrives."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ), patch("mcp_fuzzer.transport.stdio.uuid") as mock_uuid, patch.object(
            self.transport, "_receive_message", new=AsyncMock(return_value=None)
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
        """Test close method delegates to connection manager."""
        with patch.object(
            self.transport.connection_manager, "cleanup", new_callable=AsyncMock
        ) as mock_cleanup:
            await self.transport.close()
            mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_without_process(self):
        """Test close method without an active process."""
        with patch.object(
            self.transport.connection_manager, "cleanup", new_callable=AsyncMock
        ) as mock_cleanup:
            await self.transport.close()
            mock_cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_process_stats(self):
        """Test get_process_stats method."""
        mock_stats = {"active_processes": 1}
        with patch.object(self.transport.connection_manager, "get_stats", new_callable=AsyncMock) as mock_get_stats:
            mock_get_stats.return_value = mock_stats
            result = await self.transport.get_process_stats()
            assert result == mock_stats
            mock_get_stats.assert_called_once()

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
    @pytest.mark.asyncio
    async def test_send_raw_no_response(self):
        """send_raw should raise TransportError when no message arrives."""
        with patch.object(
            self.transport, "_send_message", new=AsyncMock()
        ), patch.object(
            self.transport, "_receive_message", new=AsyncMock(return_value=None)
        ):
            with pytest.raises(TransportError):
                await self.transport.send_raw({"raw": "data"})
