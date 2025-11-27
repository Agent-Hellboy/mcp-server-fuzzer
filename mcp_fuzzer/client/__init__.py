"""Public client exports."""

from .base import MCPFuzzerClient

UnifiedMCPFuzzerClient = MCPFuzzerClient

__all__ = ["MCPFuzzerClient", "UnifiedMCPFuzzerClient"]
