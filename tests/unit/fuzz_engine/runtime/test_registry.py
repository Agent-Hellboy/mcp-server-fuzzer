#!/usr/bin/env python3
"""
Unit tests for ProcessRegistry.
"""

import asyncio
import time
from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.registry import ProcessRegistry


class TestProcessRegistry:
    """Test ProcessRegistry functionality."""

    @pytest.fixture
    def registry(self):
        """Create a ProcessRegistry instance."""
        return ProcessRegistry()

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
    async def test_register_process(self, registry, mock_process, process_config):
        """Test registering a process."""
        await registry.register(mock_process.pid, mock_process, process_config)

        process_info = await registry.get_process(mock_process.pid)
        assert process_info is not None
        assert process_info["process"] == mock_process
        assert process_info["config"] == process_config
        assert process_info["status"] == "running"
        assert isinstance(process_info["started_at"], float)

    @pytest.mark.asyncio
    async def test_register_with_custom_started_at(
        self, registry, mock_process, process_config
    ):
        """Test registering with custom started_at timestamp."""
        custom_time = 1234567890.0
        await registry.register(
            mock_process.pid, mock_process, process_config, started_at=custom_time
        )

        process_info = await registry.get_process(mock_process.pid)
        assert process_info is not None
        assert process_info["started_at"] == custom_time

    @pytest.mark.asyncio
    async def test_register_with_custom_status(
        self, registry, mock_process, process_config
    ):
        """Test registering with custom status."""
        await registry.register(
            mock_process.pid, mock_process, process_config, status="stopped"
        )

        process_info = await registry.get_process(mock_process.pid)
        assert process_info is not None
        assert process_info["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_unregister_process(self, registry, mock_process, process_config):
        """Test unregistering a process."""
        await registry.register(mock_process.pid, mock_process, process_config)
        await registry.unregister(mock_process.pid)

        process_info = await registry.get_process(mock_process.pid)
        assert process_info is None

    @pytest.mark.asyncio
    async def test_unregister_nonexistent_process(self, registry):
        """Test unregistering a process that doesn't exist."""
        # Should not raise an error
        await registry.unregister(99999)

    @pytest.mark.asyncio
    async def test_get_process_nonexistent(self, registry):
        """Test getting a process that doesn't exist."""
        process_info = await registry.get_process(99999)
        assert process_info is None

    @pytest.mark.asyncio
    async def test_list_pids(self, registry, mock_process, process_config):
        """Test listing process PIDs."""
        # Initially empty
        pids = await registry.list_pids()
        assert len(pids) == 0

        # Register multiple processes
        process1 = MagicMock()
        process1.pid = 11111
        process2 = MagicMock()
        process2.pid = 22222

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        pids = await registry.list_pids()
        assert len(pids) == 2
        assert 11111 in pids
        assert 22222 in pids

    @pytest.mark.asyncio
    async def test_update_status(self, registry, mock_process, process_config):
        """Test updating process status."""
        await registry.register(mock_process.pid, mock_process, process_config)

        await registry.update_status(mock_process.pid, "stopped")
        process_info = await registry.get_process(mock_process.pid)
        assert process_info is not None
        assert process_info["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_update_status_nonexistent(self, registry):
        """Test updating status for non-existent process."""
        # Should not raise an error, just do nothing
        await registry.update_status(99999, "stopped")

    @pytest.mark.asyncio
    async def test_clear(self, registry, mock_process, process_config):
        """Test clearing all processes."""
        # Register multiple processes
        process1 = MagicMock()
        process1.pid = 11111
        process2 = MagicMock()
        process2.pid = 22222

        await registry.register(process1.pid, process1, process_config)
        await registry.register(process2.pid, process2, process_config)

        await registry.clear()

        pids = await registry.list_pids()
        assert len(pids) == 0

    @pytest.mark.asyncio
    async def test_processes_property_snapshot(
        self, registry, mock_process, process_config
    ):
        """Test that processes property returns a snapshot."""
        await registry.register(mock_process.pid, mock_process, process_config)

        snapshot1 = registry.processes
        snapshot2 = registry.processes

        # Snapshots should be independent
        assert snapshot1 == snapshot2
        assert snapshot1 is not snapshot2  # Different objects

        # Modifying snapshot shouldn't affect registry
        snapshot1[99999] = {"test": "data"}
        process_info = await registry.get_process(99999)
        assert process_info is None

    @pytest.mark.asyncio
    async def test_concurrent_register(self, registry, process_config):
        """Test concurrent registration of processes."""

        async def register_process(pid: int):
            process = MagicMock()
            process.pid = pid
            await registry.register(pid, process, process_config)

        # Register 10 processes concurrently
        tasks = [register_process(i) for i in range(10)]
        await asyncio.gather(*tasks)

        pids = await registry.list_pids()
        assert len(pids) == 10

    @pytest.mark.asyncio
    async def test_concurrent_access(self, registry, mock_process, process_config):
        """Test concurrent access to registry methods."""
        await registry.register(mock_process.pid, mock_process, process_config)

        async def read_process():
            return await registry.get_process(mock_process.pid)

        async def update_status():
            await registry.update_status(mock_process.pid, "stopped")

        async def list_pids():
            return await registry.list_pids()

        # Run multiple operations concurrently
        results = await asyncio.gather(
            read_process(),
            update_status(),
            list_pids(),
            read_process(),
        )

        # All operations should complete without errors
        assert results[0] is not None
        assert results[2] is not None
        assert len(results[2]) == 1

    @pytest.mark.asyncio
    async def test_lock_initialization(self, registry):
        """Test that lock is initialized on first use."""
        # Lock should be None initially
        assert registry._lock is None

        # First async operation should initialize lock
        await registry.list_pids()

        # Lock should now be initialized
        assert registry._lock is not None
        assert isinstance(registry._lock, asyncio.Lock)
