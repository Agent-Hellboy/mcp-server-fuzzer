#!/usr/bin/env python3
"""
Tool Client Module

This module provides functionality for fuzzing MCP tools.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..auth import AuthManager
from ..fuzz_engine.mutators import ToolMutator
from ..fuzz_engine.mutators.seed_pool import SeedPool
from ..safety_system.safety import CombinedSafetyProvider, SafetyFilter
from ..transport.interfaces import JsonRpcAdapter

from .tool_client_execution import ToolClientExecutionMixin
from .tool_client_fuzzing import ToolClientFuzzingMixin
from .tool_client_schema import ToolClientSchemaMixin


class ToolClient(
    ToolClientFuzzingMixin,
    ToolClientExecutionMixin,
    ToolClientSchemaMixin,
):
    """Client for fuzzing MCP tools."""

    def __init__(
        self,
        transport,
        auth_manager: AuthManager | None = None,
        safety_system: CombinedSafetyProvider | None = None,
        max_concurrency: int = 5,
        enable_safety: bool = True,
        corpus_root: Path | None = None,
        havoc_mode: bool = False,
        seed_pool: SeedPool | None = None,
    ):
        """
        Initialize the tool client.

        Args:
            transport: Transport protocol for server communication
            auth_manager: Authentication manager for tool authentication
            safety_system: Safety system for filtering operations
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self._rpc = JsonRpcAdapter(transport)
        self.auth_manager = auth_manager or AuthManager()
        self.enable_safety = enable_safety
        if not enable_safety:
            self.safety_system = None
        else:
            self.safety_system = safety_system or SafetyFilter()
        self.tool_mutator = ToolMutator(
            corpus_dir=corpus_root,
            havoc_mode=havoc_mode,
            seed_pool=seed_pool,
        )
        self.max_concurrency = max(1, max_concurrency)
        self._logger = logging.getLogger(__name__)
        self._tool_schema_checks: dict[str, list[dict[str, Any]]] = {}

    async def shutdown(self):
        """Shutdown the tool client."""
        pass
