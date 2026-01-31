#!/usr/bin/env python3
"""Registry for pluggable fuzzing strategies."""

from __future__ import annotations

from typing import Any, Awaitable, Callable


ProtocolStrategy = Callable[[], dict[str, Any] | None]
ToolStrategy = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]


class StrategyRegistry:
    """Registry for protocol and tool strategies with optional overrides."""

    def __init__(self) -> None:
        self._protocol: dict[tuple[str, str], ProtocolStrategy] = {}
        self._tool: dict[str, ToolStrategy] = {}

    def register_protocol(
        self,
        protocol_type: str,
        phase: str,
        strategy: ProtocolStrategy,
    ) -> None:
        self._protocol[(protocol_type, phase)] = strategy

    def unregister_protocol(self, protocol_type: str, phase: str) -> bool:
        return self._protocol.pop((protocol_type, phase), None) is not None

    def get_protocol(
        self, protocol_type: str, phase: str
    ) -> ProtocolStrategy | None:
        return self._protocol.get((protocol_type, phase))

    def register_tool(self, phase: str, strategy: ToolStrategy) -> None:
        self._tool[phase] = strategy

    def unregister_tool(self, phase: str) -> bool:
        return self._tool.pop(phase, None) is not None

    def get_tool(self, phase: str) -> ToolStrategy | None:
        return self._tool.get(phase)


strategy_registry = StrategyRegistry()

__all__ = ["StrategyRegistry", "strategy_registry"]
