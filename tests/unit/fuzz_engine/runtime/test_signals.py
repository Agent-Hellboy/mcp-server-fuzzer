#!/usr/bin/env python3
"""
Unit tests for SignalDispatcher and signal strategies.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.fuzz_engine.runtime.registry import ProcessRegistry
from mcp_fuzzer.fuzz_engine.runtime.signals import (
    InterruptSignalStrategy,
    KillSignalStrategy,
    ProcessSignalStrategy,
    SignalDispatcher,
    TermSignalStrategy,
)


class TestSignalDispatcher:
    """Test SignalDispatcher dependency injection and strategy registration."""

    @pytest.fixture
    def registry(self):
        """Create a ProcessRegistry instance."""
        return ProcessRegistry()

    @pytest.fixture
    def logger(self):
        """Create a logger instance."""
        return logging.getLogger(__name__)

    @pytest.fixture
    def dispatcher(self, registry, logger):
        """Create a SignalDispatcher with default strategies."""
        return SignalDispatcher(registry, logger)

    def test_default_strategies_registered(self, dispatcher):
        """Test that default strategies are registered by default."""
        strategies = dispatcher.list_strategies()
        assert "timeout" in strategies
        assert "force" in strategies
        assert "interrupt" in strategies
        assert len(strategies) == 3

    def test_custom_strategies_injection(self, registry, logger):
        """Test dependency injection of custom strategies."""
        custom_strategy = MagicMock(spec=ProcessSignalStrategy)
        custom_strategy.send = AsyncMock(return_value=True)

        custom_strategies = {"custom": custom_strategy}
        dispatcher = SignalDispatcher(
            registry, logger, strategies=custom_strategies, register_defaults=True
        )

        strategies = dispatcher.list_strategies()
        assert "custom" in strategies
        assert "timeout" in strategies  # Defaults still registered
        assert len(strategies) == 4

    def test_custom_strategies_only(self, registry, logger):
        """Test using only custom strategies without defaults."""
        custom_strategy = MagicMock(spec=ProcessSignalStrategy)
        custom_strategy.send = AsyncMock(return_value=True)

        custom_strategies = {"custom": custom_strategy}
        dispatcher = SignalDispatcher(
            registry, logger, strategies=custom_strategies, register_defaults=False
        )

        strategies = dispatcher.list_strategies()
        assert "custom" in strategies
        assert "timeout" not in strategies
        assert len(strategies) == 1

    def test_register_strategy_runtime(self, dispatcher):
        """Test runtime strategy registration."""
        custom_strategy = MagicMock(spec=ProcessSignalStrategy)
        custom_strategy.send = AsyncMock(return_value=True)

        dispatcher.register_strategy("custom", custom_strategy)
        strategies = dispatcher.list_strategies()
        assert "custom" in strategies

    def test_override_default_strategy(self, dispatcher):
        """Test overriding a default strategy."""
        custom_strategy = MagicMock(spec=ProcessSignalStrategy)
        custom_strategy.send = AsyncMock(return_value=True)

        dispatcher.register_strategy("timeout", custom_strategy)
        strategies = dispatcher.list_strategies()
        assert "timeout" in strategies
        assert len(strategies) == 3  # Still 3, just replaced one

    def test_unregister_strategy(self, dispatcher):
        """Test unregistering a strategy."""
        result = dispatcher.unregister_strategy("timeout")
        assert result is True
        strategies = dispatcher.list_strategies()
        assert "timeout" not in strategies

    def test_unregister_nonexistent_strategy(self, dispatcher):
        """Test unregistering a strategy that doesn't exist."""
        result = dispatcher.unregister_strategy("nonexistent")
        assert result is False
        strategies = dispatcher.list_strategies()
        assert len(strategies) == 3  # No change

    @pytest.mark.asyncio
    async def test_send_with_registered_strategy(self, dispatcher, registry, logger):
        """Test sending a signal with a registered strategy."""
        # Register a mock process
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig

        await registry.register(
            mock_process.pid, mock_process, ProcessConfig(command=["test"], name="test")
        )

        mock_strategy = MagicMock(spec=ProcessSignalStrategy)
        mock_strategy.send = AsyncMock(return_value=True)

        dispatcher = SignalDispatcher(
            registry,
            logger,
            strategies={"timeout": mock_strategy},
            register_defaults=False,
        )

        result = await dispatcher.send("timeout", mock_process.pid)
        assert result is True
        mock_strategy.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_with_unknown_strategy(self, dispatcher):
        """Test sending a signal with an unknown strategy."""
        result = await dispatcher.send("unknown", 12345)
        assert result is False

    def test_from_config_factory(self, registry, logger):
        """Test the from_config factory method."""
        custom_strategy = MagicMock(spec=ProcessSignalStrategy)
        custom_strategy.send = AsyncMock(return_value=True)

        dispatcher = SignalDispatcher.from_config(
            registry, logger, strategies={"custom": custom_strategy}
        )

        strategies = dispatcher.list_strategies()
        assert "custom" in strategies
        assert "timeout" in strategies


class TestSignalStrategies:
    """Test individual signal strategy implementations."""

    @pytest.fixture
    def registry(self):
        """Create a ProcessRegistry instance."""
        return ProcessRegistry()

    @pytest.fixture
    def logger(self):
        """Create a logger instance."""
        return logging.getLogger(__name__)

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
        from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig

        return ProcessConfig(command=["test"], name="test_process")

    @pytest.mark.asyncio
    async def test_term_signal_strategy_process_not_found(self, registry, logger):
        """Test TermSignalStrategy with process not found."""
        strategy = TermSignalStrategy(registry, logger)
        result = await strategy.send(99999)
        assert result is False

    @pytest.mark.asyncio
    async def test_term_signal_strategy_with_process(
        self, registry, logger, mock_process, process_config
    ):
        """Test TermSignalStrategy with registered process."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = TermSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    result = await strategy.send(mock_process.pid)
                    assert result is True
                    mock_killpg.assert_called_once()

    @pytest.mark.asyncio
    async def test_term_signal_strategy_fallback_to_terminate(
        self, registry, logger, mock_process, process_config
    ):
        """Test TermSignalStrategy falls back to terminate on OSError."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = TermSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", side_effect=OSError()):
                result = await strategy.send(mock_process.pid)
                assert result is True
                mock_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_kill_signal_strategy_process_not_found(self, registry, logger):
        """Test KillSignalStrategy with process not found."""
        strategy = KillSignalStrategy(registry, logger)
        result = await strategy.send(99999)
        assert result is False

    @pytest.mark.asyncio
    async def test_kill_signal_strategy_with_process(
        self, registry, logger, mock_process, process_config
    ):
        """Test KillSignalStrategy with registered process."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = KillSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    result = await strategy.send(mock_process.pid)
                    assert result is True
                    mock_killpg.assert_called_once()

    @pytest.mark.asyncio
    async def test_kill_signal_strategy_fallback_to_kill(
        self, registry, logger, mock_process, process_config
    ):
        """Test KillSignalStrategy falls back to kill on OSError."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = KillSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", side_effect=OSError()):
                result = await strategy.send(mock_process.pid)
                assert result is True
                mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_interrupt_signal_strategy_process_not_found(self, registry, logger):
        """Test InterruptSignalStrategy with process not found."""
        strategy = InterruptSignalStrategy(registry, logger)
        result = await strategy.send(99999)
        assert result is False

    @pytest.mark.asyncio
    async def test_interrupt_signal_strategy_with_process(
        self, registry, logger, mock_process, process_config
    ):
        """Test InterruptSignalStrategy with registered process."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = InterruptSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    result = await strategy.send(mock_process.pid)
                    assert result is True
                    mock_killpg.assert_called_once()

    @pytest.mark.asyncio
    async def test_interrupt_signal_strategy_fallback_to_kill(
        self, registry, logger, mock_process, process_config
    ):
        """Test InterruptSignalStrategy falls back to kill on OSError."""
        await registry.register(mock_process.pid, mock_process, process_config)

        strategy = InterruptSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", side_effect=OSError()):
                with patch("os.kill") as mock_kill:
                    result = await strategy.send(mock_process.pid)
                    assert result is True
                    mock_kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_signal_strategy_with_process_info(
        self, registry, logger, mock_process, process_config
    ):
        """Test signal strategy with provided process_info."""
        await registry.register(mock_process.pid, mock_process, process_config)
        # Get the process info
        process_info = await registry.get_process(mock_process.pid)

        strategy = TermSignalStrategy(registry, logger)

        with patch("os.name", "posix"):
            with patch("os.getpgid", return_value=12345):
                with patch("os.killpg") as mock_killpg:
                    # Pass process_info directly
                    result = await strategy.send(
                        mock_process.pid, process_info=process_info
                    )
                    assert result is True
                    mock_killpg.assert_called_once()
