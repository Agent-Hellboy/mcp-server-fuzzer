#!/usr/bin/env python3
"""
Unit tests for SignalDispatcher and signal strategies.
"""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

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
    async def test_send_with_registered_strategy(self, dispatcher, registry):
        """Test sending a signal with a registered strategy."""
        # Register a mock process
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = None

        from mcp_fuzzer.fuzz_engine.runtime.config import ProcessConfig

        await registry.register(
            mock_process.pid, mock_process, ProcessConfig(command=["test"], name="test")
        )

        # Mock the strategy's send method
        original_strategy = dispatcher._signal_map["timeout"]
        mock_strategy = MagicMock(spec=ProcessSignalStrategy)
        mock_strategy.send = AsyncMock(return_value=True)
        dispatcher._signal_map["timeout"] = mock_strategy

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

    @pytest.mark.asyncio
    async def test_term_signal_strategy(self, registry, logger):
        """Test TermSignalStrategy."""
        strategy = TermSignalStrategy(registry, logger)
        # Strategy requires a registered process to work
        # This is a basic smoke test
        assert strategy is not None

    @pytest.mark.asyncio
    async def test_kill_signal_strategy(self, registry, logger):
        """Test KillSignalStrategy."""
        strategy = KillSignalStrategy(registry, logger)
        assert strategy is not None

    @pytest.mark.asyncio
    async def test_interrupt_signal_strategy(self, registry, logger):
        """Test InterruptSignalStrategy."""
        strategy = InterruptSignalStrategy(registry, logger)
        assert strategy is not None

