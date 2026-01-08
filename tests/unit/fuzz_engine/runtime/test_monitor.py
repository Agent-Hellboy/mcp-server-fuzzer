#!/usr/bin/env python3
"""
Unit tests for ProcessInspector.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.monitor import ProcessInspector
from mcp_fuzzer.fuzz_engine.runtime.registry import ProcessRegistry


class TestProcessInspector:
    """Test ProcessInspector functionality."""

    @pytest.fixture
    def registry(self):
        """Create a ProcessRegistry instance."""
        return ProcessRegistry()

    @pytest.fixture
    def mock_watchdog(self):
        """Create a mock watchdog."""
        watchdog = AsyncMock()
        watchdog.get_stats = AsyncMock(return_value={"watchdog_active": True})
        watchdog.unregister_process = AsyncMock()
        return watchdog

    @pytest.fixture
    def logger(self):
        """Create a logger."""
        import logging

        return logging.getLogger(__name__)

    @pytest.fixture
    def inspector(self, registry, mock_watchdog, logger):
        """Create a ProcessInspector instance."""
        return ProcessInspector(registry, mock_watchdog, logger)

    @pytest.fixture
    def mock_process(self):
        """Create a mock process."""
        process = MagicMock()
        process.pid = 12345
        process.returncode = None
        return process

    @pytest.fixture
    def process_config(self):
        """Create a ProcessConfig instance."""
        return ProcessConfig(command=["test"], name="test_process")

    @pytest.mark.asyncio
    async def test_get_status_nonexistent(self, inspector):
        """Test getting status for non-existent process."""
        status = await inspector.get_status(99999)
        assert status is None

    @pytest.mark.asyncio
    async def test_get_status_running(
        self, inspector, registry, mock_process, process_config
    ):
        """Test getting status for running process."""
        await registry.register(mock_process.pid, mock_process, process_config)

        status = await inspector.get_status(mock_process.pid)
        assert status is not None
        assert status["status"] == "running"
        assert status["process"] == mock_process

    @pytest.mark.asyncio
    async def test_get_status_finished(
        self, inspector, registry, mock_process, process_config
    ):
        """Test getting status for finished process."""
        mock_process.returncode = 0
        await registry.register(mock_process.pid, mock_process, process_config)

        status = await inspector.get_status(mock_process.pid)
        assert status is not None
        assert status["status"] == "finished"
        assert status["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_get_status_stopped(
        self, inspector, registry, mock_process, process_config
    ):
        """Test getting status for stopped process."""
        await registry.register(
            mock_process.pid, mock_process, process_config, status="stopped"
        )

        status = await inspector.get_status(mock_process.pid)
        assert status is not None
        assert status["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_get_status_stopped_with_returncode(
        self, inspector, registry, mock_process, process_config
    ):
        """Test that stopped status is honored even if returncode is set."""
        mock_process.returncode = 0
        await registry.register(
            mock_process.pid, mock_process, process_config, status="stopped"
        )

        status = await inspector.get_status(mock_process.pid)
        assert status is not None
        assert status["status"] == "stopped"  # Should honor registry status

    @pytest.mark.asyncio
    async def test_list_processes_empty(self, inspector):
        """Test listing processes when registry is empty."""
        processes = await inspector.list_processes()
        assert processes == []

    @pytest.mark.asyncio
    async def test_list_processes_multiple(
        self, inspector, registry, mock_process, process_config
    ):
        """Test listing multiple processes."""
        process1 = MagicMock()
        process1.pid = 11111
        process1.returncode = None

        process2 = MagicMock()
        process2.pid = 22222
        process2.returncode = 0

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        processes = await inspector.list_processes()
        assert len(processes) == 2

        pids = {p["process"].pid for p in processes}
        assert 11111 in pids
        assert 22222 in pids

    @pytest.mark.asyncio
    async def test_list_processes_with_exceptions(
        self, inspector, registry, mock_process, process_config
    ):
        """Test list_processes handles exceptions gracefully."""
        process1 = MagicMock()
        process1.pid = 11111
        process1.returncode = None

        process2 = MagicMock()
        process2.pid = 22222
        process2.returncode = None

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        # Make get_status raise for one process
        original_get_status = inspector.get_status

        async def mock_get_status(pid):
            if pid == 11111:
                raise Exception("Test error")
            return await original_get_status(pid)

        inspector.get_status = mock_get_status

        # Should return only the successful one
        processes = await inspector.list_processes()
        assert len(processes) == 1
        assert processes[0]["process"].pid == 22222

    @pytest.mark.asyncio
    async def test_get_statistics(
        self, inspector, registry, mock_watchdog, mock_process, process_config
    ):
        """Test getting statistics."""
        process1 = MagicMock()
        process1.pid = 11111
        process1.returncode = None

        process2 = MagicMock()
        process2.pid = 22222
        process2.returncode = 0

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        stats = await inspector.get_statistics()

        assert "processes" in stats
        assert "watchdog" in stats
        assert "total_managed" in stats
        assert stats["total_managed"] == 2
        assert stats["processes"]["running"] == 1
        assert stats["processes"]["finished"] == 1

    @pytest.mark.asyncio
    async def test_cleanup_finished_processes(
        self, inspector, registry, mock_watchdog, mock_process, process_config
    ):
        """Test cleaning up finished processes."""
        process1 = MagicMock()
        process1.pid = 11111
        process1.returncode = None  # Still running

        process2 = MagicMock()
        process2.pid = 22222
        process2.returncode = 0  # Finished

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        cleaned = await inspector.cleanup_finished_processes()

        assert cleaned == 1

        # Running process should still be registered
        process_info = await registry.get_process(11111)
        assert process_info is not None

        # Finished process should be unregistered
        process_info = await registry.get_process(22222)
        assert process_info is None

    @pytest.mark.asyncio
    async def test_cleanup_finished_processes_none(
        self, inspector, registry, mock_process, process_config
    ):
        """Test cleanup when no processes are finished."""
        mock_process.returncode = None
        await registry.register(mock_process.pid, mock_process, process_config)

        cleaned = await inspector.cleanup_finished_processes()
        assert cleaned == 0

    @pytest.mark.asyncio
    async def test_wait_for_completion_not_found(self, inspector):
        """Test waiting for completion of non-existent process."""
        result = await inspector.wait_for_completion(99999)
        assert result is None

    @pytest.mark.asyncio
    async def test_wait_for_completion_already_finished(
        self, inspector, registry, mock_process, process_config
    ):
        """Test waiting for completion of already finished process."""
        mock_process.returncode = 0
        await registry.register(mock_process.pid, mock_process, process_config)

        result = await inspector.wait_for_completion(mock_process.pid)
        assert result is not None
        assert result.exit_code == 0
        assert result.timed_out is False

    @pytest.mark.asyncio
    async def test_wait_for_completion_timeout(
        self, inspector, registry, mock_process, process_config
    ):
        """Test waiting for completion with timeout."""
        mock_process.returncode = None
        await registry.register(mock_process.pid, mock_process, process_config)

        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.monitor.wait_for_process_exit",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await inspector.wait_for_completion(mock_process.pid, timeout=1.0)
            assert result is not None
            assert result.exit_code is None
            assert result.timed_out is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("timeout", [None, 5.0])
    async def test_wait_for_completion_success(
        self, inspector, registry, mock_process, process_config, timeout
    ):
        """Test waiting for completion successfully with various timeout values."""
        mock_process.returncode = None
        await registry.register(mock_process.pid, mock_process, process_config)

        # Mock wait_for_process_exit to set returncode
        async def mock_wait(process, timeout=None):
            mock_process.returncode = 0

        with patch(
            "mcp_fuzzer.fuzz_engine.runtime.monitor.wait_for_process_exit",
            side_effect=mock_wait,
        ):
            result = await inspector.wait_for_completion(
                mock_process.pid, timeout=timeout
            )
            assert result is not None
            assert result.exit_code == 0
            assert result.timed_out is False
