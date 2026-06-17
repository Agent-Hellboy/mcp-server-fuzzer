"""Paper-backed security audit phases for a fuzz session."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..diagnostics import (
    AUTH_AUDIT_PAPER_URL,
    TOOL_POISONING_PAPER_ARXIV_ID,
    discover_and_audit_authorization_server,
    is_auth_audit_finding,
    is_server_audit_finding,
    probe_advertised_auth_open_tools,
    probe_auth_bypass,
    run_server_audit,
    secured_tool_names,
    server_audit_paper_evidence,
)
from ..transport.bootstrap import build_driver_with_auth
from ..transport.interfaces import JsonRpcAdapter

logger = logging.getLogger(__name__)


def _oauth_provider(config: dict[str, Any]) -> Any | None:
    auth_manager = config.get("auth_manager")
    if auth_manager is None:
        return None
    providers = getattr(auth_manager, "auth_providers", {}) or {}
    return providers.get("mcp_oauth")


def _oauth_client_id(config: dict[str, Any]) -> str | None:
    provider = _oauth_provider(config)
    if provider is None:
        return None
    provider_config = getattr(provider, "config", None)
    if provider_config is None:
        return None
    return getattr(provider_config, "client_id", None)


async def run_auth_bypass_phase(
    config: dict[str, Any],
    build_transport_request: Any,
) -> list[Any]:
    """Probe configured-but-unenforced auth by calling tools without credentials."""
    auth_manager = config.get("auth_manager")
    if auth_manager is None:
        return []
    try:
        unauth_request = build_transport_request({**config, "auth_manager": None})
        unauth_transport = build_driver_with_auth(unauth_request)
        adapter = JsonRpcAdapter(unauth_transport)
        try:
            tools = await adapter.get_tools()
        except Exception:
            return []
        secured = secured_tool_names(auth_manager, tools)
        if not secured:
            return []

        async def attempt(tool_name: str) -> Any:
            return await adapter.call_tool(tool_name, {})

        try:
            return await probe_auth_bypass(secured, attempt)
        finally:
            close = getattr(unauth_transport, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception:
                    pass
    except Exception as exc:  # pragma: no cover - probe is best-effort
        logger.debug("Auth-bypass probe skipped: %s", exc)
        return []


async def run_oauth_audit_phase(
    config: dict[str, Any],
    transport: Any,
    build_transport_request: Any,
) -> tuple[list[Any], bool]:
    """Run arXiv 2605.22333 authorization-server and MCP auth boundary checks."""
    if not config.get("auth_audit"):
        return [], False
    if config.get("no_network"):
        logging.warning("Auth audit skipped: --no-network is set")
        return [], False
    probe = getattr(transport, "probe_auth_discovery", None)
    if not callable(probe):
        logging.warning(
            "Auth audit skipped: transport does not support auth discovery "
            "(requires an HTTP/SSE remote endpoint)"
        )
        return [], False
    try:
        import httpx

        hints = await probe()
        www_authenticate = hints.get("www_authenticate")
        auth_advertised = (
            hints.get("status") == 401
            or bool(www_authenticate)
            or _oauth_provider(config) is not None
        )
        timeout = float(config.get("timeout", 30.0))
        intrusive = bool(config.get("auth_audit_intrusive"))
        client_id = _oauth_client_id(config)
        endpoint = config["endpoint"]
        findings: list[Any] = []

        def _discover() -> list[Any]:
            with httpx.Client(timeout=timeout, follow_redirects=True) as http:
                return discover_and_audit_authorization_server(
                    endpoint,
                    www_authenticate=www_authenticate,
                    http=http,
                    intrusive=intrusive,
                    client_id=client_id,
                )

        findings.extend(await asyncio.to_thread(_discover))
        if auth_advertised:
            unauth_request = build_transport_request(
                {**config, "auth_manager": None}
            )
            unauth_transport = build_driver_with_auth(unauth_request)
            adapter = JsonRpcAdapter(unauth_transport)
            try:
                tools = await adapter.get_tools()
            except Exception:
                tools = []
            else:
                if isinstance(tools, list):
                    findings.extend(
                        probe_advertised_auth_open_tools(
                            tools, auth_advertised=True
                        )
                    )
            finally:
                close = getattr(unauth_transport, "close", None)
                if callable(close):
                    try:
                        await close()
                    except Exception:
                        pass
        return findings, True
    except Exception as exc:  # pragma: no cover - probe is best-effort
        logging.warning("Auth audit skipped after an error: %s", exc)
        return [], False


async def run_server_audit_phase(
    config: dict[str, Any],
    transport: Any,
    tool_results: dict[str, Any] | None,
) -> tuple[list[Any], bool]:
    """Run tool-metadata and active-oracle server checks from the 0.4.0 roadmap."""
    if not config.get("security_audit"):
        return [], False
    try:
        tools: list[dict[str, Any]] = []
        adapter = JsonRpcAdapter(transport)
        try:
            raw = await adapter.get_tools()
            if isinstance(raw, list):
                tools = [t for t in raw if isinstance(t, dict)]
        except Exception:
            pass
        findings = run_server_audit(
            tools,
            endpoint=str(config.get("endpoint") or ""),
            tool_results=tool_results,
        )
        return findings, True
    except Exception as exc:  # pragma: no cover - probe is best-effort
        logging.warning("Server audit skipped after an error: %s", exc)
        return [], False


def log_oauth_audit_results(
    findings: list[Any], *, enabled: bool, ran: bool
) -> None:
    if not enabled or not ran:
        return
    auth_audit_findings = [f for f in findings if is_auth_audit_finding(f)]
    if auth_audit_findings:
        logging.warning(
            "Auth security audit recorded %d finding(s) mapped to arXiv "
            "2605.22333 flaw types: %s",
            len(auth_audit_findings),
            AUTH_AUDIT_PAPER_URL,
        )
    else:
        logging.info(
            "Auth security audit complete with no findings (taxonomy: %s)",
            AUTH_AUDIT_PAPER_URL,
        )


def log_server_audit_results(
    findings: list[Any], *, enabled: bool, ran: bool
) -> None:
    if not enabled or not ran:
        return
    server_findings = [f for f in findings if is_server_audit_finding(f)]
    paper = server_audit_paper_evidence(TOOL_POISONING_PAPER_ARXIV_ID)
    if server_findings:
        logging.warning(
            "Server audit recorded %d finding(s) (taxonomy: arXiv %s — %s)",
            len(server_findings),
            TOOL_POISONING_PAPER_ARXIV_ID,
            paper["paper_url"],
        )
    else:
        logging.info(
            "Server audit complete with no findings (taxonomy: %s)",
            paper["paper_url"],
        )


__all__ = [
    "run_auth_bypass_phase",
    "run_oauth_audit_phase",
    "run_server_audit_phase",
    "log_oauth_audit_results",
    "log_server_audit_results",
]
