"""Tests for orchestrator audit phase wiring."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.diagnostics.model import Finding
from mcp_fuzzer.orchestrator import audit_phases as phases


def _auth_finding() -> Finding:
    return Finding(
        category="weak_state",
        severity="high",
        kind="auth",
        target="auth.example",
        run=None,
        detail="weak state",
        evidence={"flaw_id": "F5"},
    )


def _server_finding() -> Finding:
    return Finding(
        category="tool_poisoning",
        severity="high",
        kind="tool",
        target="helper",
        run=None,
        detail="poisoned",
        evidence={"check_id": "metadata-1"},
    )


@pytest.mark.asyncio
async def test_run_auth_bypass_phase_returns_findings():
    auth_manager = MagicMock()
    config = {"auth_manager": auth_manager}
    transport = AsyncMock()
    finding = _auth_finding()

    with (
        patch.object(phases, "secured_tool_names", return_value={"secret"}),
        patch.object(
            phases, "probe_auth_bypass", new=AsyncMock(return_value=[finding])
        ),
        patch.object(phases, "build_driver_with_auth", return_value=transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
    ):
        adapter = mock_adapter_cls.return_value
        adapter.get_tools = AsyncMock(return_value=[{"name": "secret"}])
        adapter.call_tool = AsyncMock()

        result = await phases.run_auth_bypass_phase(config, lambda c: MagicMock())

    assert result == [finding]
    transport.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_auth_bypass_phase_no_secured_tools():
    auth_manager = MagicMock()
    transport = MagicMock()

    with (
        patch.object(phases, "secured_tool_names", return_value=set()),
        patch.object(phases, "build_driver_with_auth", return_value=transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(return_value=[])

        result = await phases.run_auth_bypass_phase(
            {"auth_manager": auth_manager}, lambda c: MagicMock()
        )

    assert result == []


@pytest.mark.asyncio
async def test_run_auth_bypass_phase_get_tools_failure():
    auth_manager = MagicMock()
    transport = MagicMock()

    with (
        patch.object(phases, "build_driver_with_auth", return_value=transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(
            side_effect=RuntimeError("boom")
        )

        result = await phases.run_auth_bypass_phase(
            {"auth_manager": auth_manager}, lambda c: MagicMock()
        )

    assert result == []


def test_oauth_client_id_none_when_provider_config_missing():
    config = {
        "auth_manager": SimpleNamespace(
            auth_providers={"mcp_oauth": SimpleNamespace(config=None)}
        )
    }
    assert phases._oauth_client_id(config) is None


@pytest.mark.asyncio
async def test_run_auth_bypass_phase_outer_exception():
    with patch.object(
        phases,
        "build_driver_with_auth",
        side_effect=RuntimeError("transport failed"),
    ):
        result = await phases.run_auth_bypass_phase(
            {"auth_manager": MagicMock()}, lambda c: MagicMock()
        )

    assert result == []


@pytest.mark.asyncio
async def test_run_auth_bypass_phase_close_failure_still_returns_findings():
    auth_manager = MagicMock()
    finding = _auth_finding()
    transport = AsyncMock()
    transport.close = AsyncMock(side_effect=RuntimeError("close failed"))

    with (
        patch.object(phases, "secured_tool_names", return_value={"secret"}),
        patch.object(
            phases, "probe_auth_bypass", new=AsyncMock(return_value=[finding])
        ),
        patch.object(phases, "build_driver_with_auth", return_value=transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(return_value=[{}])

        result = await phases.run_auth_bypass_phase(
            {"auth_manager": auth_manager}, lambda c: MagicMock()
        )

    assert result == [finding]


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_uses_oauth_client_id():
    transport = MagicMock()
    transport.probe_auth_discovery = AsyncMock(return_value={"status": 200})
    config = {
        "auth_audit": True,
        "endpoint": "https://mcp.example/mcp",
        "auth_manager": SimpleNamespace(
            auth_providers={
                "mcp_oauth": SimpleNamespace(config=SimpleNamespace(client_id="cid-1"))
            }
        ),
    }

    with (
        patch.object(
            phases,
            "discover_and_audit_authorization_server",
            return_value=[],
        ) as mock_discover,
        patch.object(phases, "build_driver_with_auth", return_value=AsyncMock()),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "probe_advertised_auth_open_tools", return_value=[]),
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(return_value=[])

        await phases.run_oauth_audit_phase(config, transport, lambda c: MagicMock())

    assert mock_discover.call_args.kwargs["client_id"] == "cid-1"


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_get_tools_failure_still_ran():
    transport = MagicMock()
    transport.probe_auth_discovery = AsyncMock(return_value={"status": 401})

    with (
        patch.object(
            phases,
            "discover_and_audit_authorization_server",
            return_value=[],
        ),
        patch.object(phases, "build_driver_with_auth", return_value=AsyncMock()),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(
            side_effect=RuntimeError("tools failed")
        )

        findings, ran = await phases.run_oauth_audit_phase(
            {"auth_audit": True, "endpoint": "https://mcp.example/mcp"},
            transport,
            lambda c: MagicMock(),
        )

    assert findings == []
    assert ran is True


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_close_failure_still_returns_findings():
    finding = _auth_finding()
    transport = MagicMock()
    transport.probe_auth_discovery = AsyncMock(return_value={"status": 401})
    unauth_transport = AsyncMock()
    unauth_transport.close = AsyncMock(side_effect=RuntimeError("close failed"))

    with (
        patch.object(
            phases,
            "discover_and_audit_authorization_server",
            return_value=[finding],
        ),
        patch.object(phases, "build_driver_with_auth", return_value=unauth_transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "probe_advertised_auth_open_tools", return_value=[]),
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(return_value=[])

        findings, ran = await phases.run_oauth_audit_phase(
            {"auth_audit": True, "endpoint": "https://mcp.example/mcp"},
            transport,
            lambda c: MagicMock(),
        )

    assert ran is True
    assert findings == [finding]


@pytest.mark.asyncio
async def test_run_server_audit_phase_handles_tool_list_errors():
    transport = MagicMock()
    finding = _server_finding()

    with (
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "run_server_audit", return_value=[finding]),
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(
            side_effect=RuntimeError("list failed")
        )

        findings, ran = await phases.run_server_audit_phase(
            {"security_audit": True, "endpoint": "http://localhost"},
            transport,
            None,
        )

    assert ran is True
    assert findings == [finding]


def test_log_server_audit_results_skipped_when_disabled():
    phases.log_server_audit_results([_server_finding()], enabled=False, ran=True)


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_skips_on_no_network(caplog):
    with caplog.at_level(logging.WARNING):
        findings, ran = await phases.run_oauth_audit_phase(
            {"auth_audit": True, "no_network": True},
            MagicMock(),
            lambda c: c,
        )

    assert findings == []
    assert ran is False
    assert "no-network" in caplog.text


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_runs_discovery_and_open_tools():
    finding = _auth_finding()
    transport = MagicMock()
    transport.probe_auth_discovery = AsyncMock(
        return_value={"status": 401, "www_authenticate": "Bearer realm=x"}
    )
    unauth_transport = AsyncMock()
    config = {
        "auth_audit": True,
        "endpoint": "https://mcp.example/mcp",
        "timeout": 5.0,
        "auth_audit_intrusive": False,
        "auth_manager": SimpleNamespace(
            auth_providers={
                "mcp_oauth": SimpleNamespace(config=SimpleNamespace(client_id="cid"))
            }
        ),
    }

    with (
        patch.object(
            phases,
            "discover_and_audit_authorization_server",
            return_value=[finding],
        ),
        patch.object(phases, "build_driver_with_auth", return_value=unauth_transport),
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(
            phases,
            "probe_advertised_auth_open_tools",
            return_value=[finding],
        ),
    ):
        adapter = mock_adapter_cls.return_value
        adapter.get_tools = AsyncMock(return_value=[{"name": "open"}])

        findings, ran = await phases.run_oauth_audit_phase(
            config, transport, lambda c: MagicMock()
        )

    assert ran is True
    assert len(findings) >= 2
    unauth_transport.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_oauth_audit_phase_handles_discovery_error(caplog):
    transport = MagicMock()
    transport.probe_auth_discovery = AsyncMock(side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.WARNING):
        findings, ran = await phases.run_oauth_audit_phase(
            {"auth_audit": True, "endpoint": "https://mcp.example/mcp"},
            transport,
            lambda c: c,
        )

    assert findings == []
    assert ran is False
    assert "skipped after an error" in caplog.text


@pytest.mark.asyncio
async def test_run_server_audit_phase_disabled():
    findings, ran = await phases.run_server_audit_phase(
        {"security_audit": False}, MagicMock(), None
    )
    assert findings == []
    assert ran is False


@pytest.mark.asyncio
async def test_run_server_audit_phase_runs_checks():
    finding = _server_finding()
    transport = MagicMock()

    with (
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "run_server_audit", return_value=[finding]) as mock_audit,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(
            return_value=[{"name": "helper"}]
        )

        findings, ran = await phases.run_server_audit_phase(
            {"security_audit": True, "endpoint": "http://localhost:8080"},
            transport,
            {"helper": []},
        )

    assert ran is True
    assert findings == [finding]
    mock_audit.assert_called_once()


@pytest.mark.asyncio
async def test_run_server_audit_phase_runs_intrusive_origin_probe():
    finding = _server_finding()
    origin_finding = Finding(
        category="missing_origin_validation",
        severity="high",
        kind="tool",
        target="mcp_endpoint",
        run=None,
        detail="foreign origin accepted",
        evidence={"check_id": "OR1"},
    )
    transport = MagicMock()

    with (
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "run_server_audit", return_value=[finding]),
        patch.object(
            phases, "audit_origin_validation", return_value=[origin_finding]
        ) as mock_origin,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(
            return_value=[{"name": "helper"}]
        )

        findings, ran = await phases.run_server_audit_phase(
            {
                "security_audit": True,
                "security_audit_intrusive": True,
                "endpoint": "https://mcp.example/mcp",
                "protocol": "streamablehttp",
                "spec_schema_version": "2026-07-28",
                "timeout": 5,
            },
            transport,
            None,
        )

    assert ran is True
    assert findings == [finding, origin_finding]
    mock_origin.assert_called_once_with(
        "https://mcp.example/mcp",
        protocol="streamablehttp",
        protocol_version="2026-07-28",
        timeout=5.0,
        auth_headers={},
    )


@pytest.mark.asyncio
async def test_run_server_audit_phase_forwards_transport_auth_to_origin_probe():
    """A server that authenticates before checking Origin must still be probed."""
    auth_manager = MagicMock()
    auth_manager.get_default_auth_headers.return_value = {
        "Authorization": "Bearer token-123"
    }

    with (
        patch.object(phases, "JsonRpcAdapter") as mock_adapter_cls,
        patch.object(phases, "run_server_audit", return_value=[]),
        patch.object(
            phases, "audit_origin_validation", return_value=[]
        ) as mock_origin,
    ):
        mock_adapter_cls.return_value.get_tools = AsyncMock(return_value=[])

        await phases.run_server_audit_phase(
            {
                "security_audit": True,
                "security_audit_intrusive": True,
                "endpoint": "https://mcp.example/mcp",
                "auth_manager": auth_manager,
            },
            MagicMock(),
            None,
        )

    assert mock_origin.call_args.kwargs["auth_headers"] == {
        "Authorization": "Bearer token-123"
    }


def test_transport_auth_headers_handles_missing_and_broken_providers():
    assert phases._transport_auth_headers({}) == {}

    without_getter = MagicMock(spec=[])
    assert phases._transport_auth_headers({"auth_manager": without_getter}) == {}

    raising = MagicMock()
    raising.get_default_auth_headers.side_effect = RuntimeError("boom")
    assert phases._transport_auth_headers({"auth_manager": raising}) == {}

    non_dict = MagicMock()
    non_dict.get_default_auth_headers.return_value = ["not", "a", "dict"]
    assert phases._transport_auth_headers({"auth_manager": non_dict}) == {}


def test_log_oauth_audit_results_reports_findings(caplog):
    with caplog.at_level(logging.WARNING):
        phases.log_oauth_audit_results([_auth_finding()], enabled=True, ran=True)

    assert "recorded 1 finding" in caplog.text


def test_log_oauth_audit_results_reports_clean_run(caplog):
    with caplog.at_level(logging.INFO):
        phases.log_oauth_audit_results([], enabled=True, ran=True)

    assert "complete with no findings" in caplog.text


def test_log_server_audit_results_reports_findings(caplog):
    with caplog.at_level(logging.WARNING):
        phases.log_server_audit_results([_server_finding()], enabled=True, ran=True)

    assert "recorded 1 finding" in caplog.text


def test_log_server_audit_results_reports_clean_run(caplog):
    with caplog.at_level(logging.INFO):
        phases.log_server_audit_results([], enabled=True, ran=True)

    assert "complete with no findings" in caplog.text
