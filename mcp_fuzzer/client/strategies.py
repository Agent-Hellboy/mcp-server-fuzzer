#!/usr/bin/env python3
"""Client execution strategies using Strategy Pattern."""

from typing import Any, Protocol

from ..config import DEFAULT_PROTOCOL_RUNS_PER_TYPE, DEFAULT_TOOL_RUNS


class FuzzingStrategy(Protocol):
    """Interface for different fuzzing execution strategies."""

    def can_handle(self, mode: str) -> bool:
        """Check if this strategy can handle the given mode."""
        ...

    async def execute(self, client, config: dict[str, Any]) -> None:
        """Execute fuzzing using the given client and configuration."""
        ...


class ToolFuzzingStrategy:
    """Strategy for fuzzing MCP tools."""

    def can_handle(self, mode: str) -> bool:
        return mode in ["tools", "both"]

    async def execute(self, client, config: dict[str, Any]) -> None:
        """Execute tool fuzzing."""
        phase = config.get("phase", "aggressive")

        if phase == "both":
            await client.fuzz_all_tools_both_phases(
                runs_per_phase=config.get("runs", DEFAULT_TOOL_RUNS)
            )
        else:
            await client.fuzz_all_tools(
                runs_per_tool=config.get("runs", DEFAULT_TOOL_RUNS)
            )


class ProtocolFuzzingStrategy:
    """Strategy for fuzzing MCP protocol types."""

    def can_handle(self, mode: str) -> bool:
        return mode in ["protocol", "both"]

    async def execute(self, client, config: dict[str, Any]) -> None:
        """Execute protocol fuzzing."""
        protocol_type = config.get("protocol_type")

        if protocol_type:
            await client.fuzz_protocol_type(
                protocol_type,
                runs=config.get("runs_per_type", DEFAULT_PROTOCOL_RUNS_PER_TYPE),
            )
        else:
            await client.fuzz_all_protocol_types(
                runs_per_type=config.get(
                    "runs_per_type", DEFAULT_PROTOCOL_RUNS_PER_TYPE
                ),
            )


class CombinedFuzzingStrategy:
    """Strategy for combined tool and protocol fuzzing."""

    def __init__(self):
        self.tool_strategy = ToolFuzzingStrategy()
        self.protocol_strategy = ProtocolFuzzingStrategy()

    def can_handle(self, mode: str) -> bool:
        return mode == "both"

    async def execute(self, client, config: dict[str, Any]) -> None:
        """Execute both tool and protocol fuzzing."""
        # Execute tools first
        await self.tool_strategy.execute(client, config)
        # Then execute protocols
        await self.protocol_strategy.execute(client, config)


def get_fuzzing_strategies() -> list[FuzzingStrategy]:
    """Get all available fuzzing strategies."""
    return [
        ToolFuzzingStrategy(),
        ProtocolFuzzingStrategy(),
        CombinedFuzzingStrategy(),
    ]
