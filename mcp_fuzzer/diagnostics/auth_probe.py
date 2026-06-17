"""Active auth-bypass probe.

When authentication is configured, a correctly-implemented MCP server must
reject unauthenticated calls to protected tools with 401/403. This probe issues
unauthenticated calls and flags any protected tool that responds *successfully*
without auth -- a high-severity auth-bypass finding.

The classification logic is pure and unit-tested; the network attempt is
injected so callers (and tests) control how the unauthenticated call is made.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from ..exceptions import AuthenticationError
from .model import Finding
from .auth_oauth import auth_audit_paper_evidence

logger = logging.getLogger(__name__)

_AUTH_DENIED_MARKERS = (
    "401",
    "403",
    "unauthorized",
    "forbidden",
    "authentication required",
    "not authenticated",
    "invalid token",
    "missing token",
    "access denied",
)


def is_auth_enforced(
    *, response: Any = None, exception: BaseException | None = None
) -> bool:
    """Return True if the unauthenticated attempt was denied (auth enforced).

    Conservative: only an explicit auth denial (401/403/auth error) counts as
    enforced. A successful result -- or any non-auth error -- means auth was NOT
    enforced for this call, which is the bypass signal.
    """
    if exception is not None:
        if isinstance(exception, AuthenticationError):
            return True
        text = str(exception).lower()
        return any(marker in text for marker in _AUTH_DENIED_MARKERS)
    if isinstance(response, dict):
        error = response.get("error")
        if isinstance(error, dict):
            text = f"{error.get('code', '')} {error.get('message', '')}".lower()
            return any(marker in text for marker in _AUTH_DENIED_MARKERS)
        if isinstance(error, str):
            return any(marker in error.lower() for marker in _AUTH_DENIED_MARKERS)
    # A successful response (or unrecognized error) => auth was not enforced.
    return False


async def probe_auth_bypass(
    secured_tools: list[str],
    attempt: Callable[[str], Awaitable[Any]],
) -> list[Finding]:
    """Probe each secured tool with an unauthenticated call.

    ``attempt(tool_name)`` performs the unauthenticated call and returns the
    server response (or raises). Returns an ``auth_bypass`` finding for every
    tool that was *not* denied.
    """
    findings: list[Finding] = []
    for tool_name in secured_tools:
        try:
            response = await attempt(tool_name)
            enforced = is_auth_enforced(response=response)
        except Exception as exc:  # noqa: BLE001 - any error is classified
            enforced = is_auth_enforced(exception=exc)
            response = None
        if not enforced:
            findings.append(
                Finding(
                    "auth_bypass",
                    "high",
                    "tool",
                    tool_name,
                    None,
                    "Tool was callable without authentication even though auth "
                    "is configured (auth not enforced for this tool).",
                    {"unauthenticated_response": _truncate(response)},
                )
            )
    return findings


def probe_advertised_auth_open_tools(
    tools: list[dict[str, Any]],
    *,
    auth_advertised: bool = True,
) -> list[Finding]:
    """Flag tools/list succeeding without credentials when OAuth auth is advertised.

    Mirrors the paper's measurement of remote MCP servers that expose tools
    without authentication despite advertising an authorization boundary.
    """
    if not auth_advertised:
        return []
    names = [
        str(t.get("name"))
        for t in tools
        if isinstance(t, dict) and t.get("name")
    ]
    if not names:
        return []
    return [
        Finding(
            "unauthenticated_tools",
            "high",
            "auth",
            "mcp_endpoint",
            None,
            f"Server advertises OAuth authorization but exposed {len(names)} "
            "tool(s) without authentication (tools/list callable with no "
            "credentials).",
            {
                "paper_finding": "unauthenticated_tool_exposure",
                **auth_audit_paper_evidence(),
                "tool_count": len(names),
                "tool_names": names[:20],
            },
        )
    ]


def secured_tool_names(auth_manager: Any, tools: list[dict[str, Any]]) -> list[str]:
    """Determine which discovered tools are expected to require authentication."""
    if auth_manager is None:
        return []
    names = [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]
    mapping = getattr(auth_manager, "tool_auth_mapping", {}) or {}
    default_provider = getattr(auth_manager, "default_provider", None)
    if default_provider:
        # A default provider means every call is authenticated.
        return [str(n) for n in names]
    return [str(n) for n in names if n in mapping]


def _truncate(value: Any, limit: int = 300) -> Any:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"
