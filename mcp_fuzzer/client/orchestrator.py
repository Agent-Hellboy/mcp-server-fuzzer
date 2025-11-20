#!/usr/bin/env python3
"""Client Orchestrator using Strategy Pattern for clean execution."""

import logging
from typing import Any

from .base import MCPFuzzerClient
from .strategies import get_fuzzing_strategies


class ClientOrchestrator:
    """Orchestrates client execution using strategy pattern."""

    def __init__(self, client: MCPFuzzerClient):
        self.client = client
        self.strategies = get_fuzzing_strategies()
        self.logger = logging.getLogger(__name__)

    async def execute_fuzzing(self, config: dict[str, Any]) -> None:
        """Execute fuzzing based on configuration."""
        mode = config.get("mode", "both")

        # Find and execute appropriate strategy
        for strategy in self.strategies:
            if strategy.can_handle(mode):
                self.logger.info(f"Executing fuzzing mode: {mode}")
                await strategy.execute(self.client, config)
                return

        raise ValueError(f"Unsupported fuzzing mode: {mode}")

    async def execute_with_error_handling(self, config: dict[str, Any]) -> int:
        """Execute fuzzing with comprehensive error handling."""
        try:
            await self.execute_fuzzing(config)
            return 0
        except Exception as e:
            self.logger.error(f"Fuzzing execution failed: {e}")
            return 1
