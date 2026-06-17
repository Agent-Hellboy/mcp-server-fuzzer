"""Tool schema discovery and spec-check attachment for ToolClient."""

from __future__ import annotations

import logging
from typing import Any

from .. import spec_guard


class ToolClientSchemaMixin:
    """Fetch tools from the server and track schema spec checks."""

    _logger: logging.Logger
    _tool_schema_checks: dict[str, list[dict[str, Any]]]
    _rpc: Any

    async def _get_tools_from_server(self) -> list[dict[str, Any]]:
        """Get tools from the server."""
        try:
            tools = await self._rpc.get_tools()
            if not tools:
                self._logger.warning("Server returned an empty list of tools.")
                return []
            self._logger.info("Found %d tools to fuzz", len(tools))
            self._tool_schema_checks.clear()
            for tool in tools:
                tool_name = tool.get("name", "unknown")
                checks = spec_guard.check_tool_schema_fields(tool)
                if checks:
                    self._tool_schema_checks[tool_name] = checks
            self._logger.debug("Tools: %s", tools)
            return tools
        except Exception as e:
            self._logger.error("Failed to get tools from server: %s", e)
            return []

    def _attach_schema_checks(self, tool_name: str, entry: dict[str, Any]) -> None:
        if tool_name not in self._tool_schema_checks:
            return
        schema_checks = self._tool_schema_checks[tool_name]
        entry["spec_checks"] = schema_checks
        entry["spec_scope"] = "tool_schema"
        entry["spec_checks_passed"] = not any(
            str(check.get("status", "")).upper() == "FAIL"
            for check in schema_checks
        )
