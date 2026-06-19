"""Structured tool-discovery diagnostics for CI-friendly run summaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class ToolDiscoveryFailure(StrEnum):
    """Machine-readable reason when ``tools/list`` yields nothing to fuzz."""

    NONE = "none"
    CONNECTION_FAILED = "connection_failed"
    AUTH_REQUIRED = "auth_required"
    EMPTY_TOOLS_LIST = "empty_tools_list"
    SERVER_ERROR = "server_error"
    STDIO_PARSE_ERROR = "stdio_parse_error"
    PROCESS_CRASHED = "process_crashed"
    OUTPUT_NOT_WRITABLE = "output_not_writable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ToolDiscoveryReport:
    """Outcome of the last ``tools/list`` attempt."""

    failure: ToolDiscoveryFailure = ToolDiscoveryFailure.NONE
    detail: str = ""
    tool_count: int = 0

    @property
    def ok(self) -> bool:
        return self.failure is ToolDiscoveryFailure.NONE and self.tool_count > 0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["failure"] = self.failure.value
        return payload

    @classmethod
    def success(cls, tool_count: int) -> ToolDiscoveryReport:
        return cls(
            failure=ToolDiscoveryFailure.NONE,
            detail=f"Discovered {tool_count} tool(s)",
            tool_count=tool_count,
        )

    @classmethod
    def failed(
        cls,
        code: ToolDiscoveryFailure,
        detail: str,
        *,
        tool_count: int = 0,
    ) -> ToolDiscoveryReport:
        return cls(failure=code, detail=detail, tool_count=tool_count)


def classify_tool_discovery_error(exc: BaseException) -> ToolDiscoveryReport:
    """Map transport/client exceptions to a stable discovery failure code."""
    message = str(exc).lower()
    if "failed to receive message" in message or "expecting value" in message:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.STDIO_PARSE_ERROR,
            "Server stdout was not valid JSON-RPC "
            "(log lines on stdout break stdio MCP)",
        )
    if "no response received" in message:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.STDIO_PARSE_ERROR,
            "No JSON-RPC response on stdio "
            "(server may still be starting or logging to stdout)",
        )
    if "connection failed" in message or "connect" in message:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.CONNECTION_FAILED,
            str(exc),
        )
    if "terminated abnormally" in message or "crashed" in message:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.PROCESS_CRASHED,
            str(exc),
        )
    if "401" in message or "403" in message or "unauthorized" in message:
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.AUTH_REQUIRED,
            str(exc),
        )
    return ToolDiscoveryReport.failed(ToolDiscoveryFailure.UNKNOWN, str(exc))


def classify_tools_list_response(
    response: dict[str, Any],
) -> ToolDiscoveryReport | None:
    """Return a failure report when ``tools/list`` responded without tools."""
    if "error" in response:
        error = response.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            msg = str(error.get("message", error))
            if code in (-32001, 401, 403) or "unauthorized" in msg.lower():
                return ToolDiscoveryReport.failed(
                    ToolDiscoveryFailure.AUTH_REQUIRED,
                    msg,
                )
            return ToolDiscoveryReport.failed(
                ToolDiscoveryFailure.SERVER_ERROR,
                msg,
            )
        return ToolDiscoveryReport.failed(
            ToolDiscoveryFailure.SERVER_ERROR,
            str(error),
        )
    return None


__all__ = [
    "ToolDiscoveryFailure",
    "ToolDiscoveryReport",
    "classify_tool_discovery_error",
    "classify_tools_list_response",
]
