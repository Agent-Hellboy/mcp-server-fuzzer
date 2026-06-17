"""Tests for the CLI app composition root."""

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mcp_fuzzer.cli.app as fuzz_app
import mcp_fuzzer.cli.bootstrap as bootstrap
from mcp_fuzzer.cli.app import run_fuzz_app
from mcp_fuzzer.orchestrator.run_plan import _run_spec_guard_if_enabled
from mcp_fuzzer.client.settings import ClientSettings
from mcp_fuzzer.exceptions import MCPError


def _settings(**overrides):
    base = dict(
        mode="tools",
        phase="aggressive",
        protocol="http",
        endpoint="http://localhost",
        timeout=30.0,
        runs=1,
        runs_per_type=1,
        safety_enabled=True,
        fs_root=None,
        output_dir="reports",
        safety_report=False,
        auth_manager=None,
        tool=None,
        tool_timeout=None,
        protocol_type=None,
    )
    base.update(overrides)
    return ClientSettings(base)


def _make_reporter():
    reporter = MagicMock()
    reporter.export_format = AsyncMock()
    reporter.generate_standardized_report = AsyncMock(return_value={})
    reporter.export_requested_formats = AsyncMock(return_value={})
    reporter.set_fuzzing_metadata = MagicMock()
    return reporter


def test_run_fuzz_app_tools_mode():
    settings = _settings()
    mock_transport = MagicMock()
    mock_safety = MagicMock()
    mock_reporter = _make_reporter()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(
        return_value={"tool1": [{"result": "ok"}]}
    )
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = mock_reporter

    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=mock_transport,
        ) as mock_transport_factory,
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=mock_safety),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=mock_reporter),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(run_fuzz_app(settings))

    assert rc == 0
    mock_transport_factory.assert_called_once()
    assert client_instance.fuzz_all_tools.await_count == 1
    client_instance.cleanup.assert_awaited()
    mock_reporter.export_requested_formats.assert_awaited_once_with(
        {},
        include_safety=False,
    )


def test_run_fuzz_app_unknown_mode_logs_error_and_returns_nonzero():
    settings = _settings(mode="unknown")
    client_instance = MagicMock()
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = _make_reporter()
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(run_fuzz_app(settings))
    assert rc == 1
    client_instance.cleanup.assert_awaited()


def test_run_fuzz_app_sets_fs_root_when_provided():
    settings = _settings(fs_root="/tmp/safe")
    mock_safety = MagicMock()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = _make_reporter()

    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=mock_safety),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(run_fuzz_app(settings))

    mock_safety.set_fs_root.assert_called_once_with("/tmp/safe")


def test_run_fuzz_app_protocol_and_both_modes():
    # Protocol mode without protocol_type
    settings = _settings(mode="protocol", runs_per_type=2)
    client_instance = MagicMock()
    client_instance.fuzz_all_protocol_types = AsyncMock()
    client_instance.run_spec_suite = AsyncMock(return_value=[])
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = _make_reporter()
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(run_fuzz_app(settings))
    client_instance.fuzz_all_protocol_types.assert_awaited()
    client_instance.run_spec_suite.assert_awaited()

    # Both mode with phase both and protocol_type set
    settings_both = _settings(mode="all", phase="both", protocol_type="Init")
    client_instance2 = MagicMock()
    client_instance2.fuzz_all_tools_both_phases = AsyncMock()
    client_instance2.fuzz_protocol_type = AsyncMock()
    client_instance2.run_spec_suite = AsyncMock(return_value=[])
    client_instance2.cleanup = AsyncMock()
    client_instance2.reporter = _make_reporter()
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch(
            "mcp_fuzzer.cli.bootstrap.MCPFuzzerClient",
            return_value=client_instance2,
        ),
    ):
        asyncio.run(run_fuzz_app(settings_both))
    client_instance2.fuzz_all_tools_both_phases.assert_awaited()
    client_instance2.fuzz_protocol_type.assert_awaited()
    client_instance2.run_spec_suite.assert_awaited()


def test_run_fuzz_app_exports_reports_and_handles_errors():
    settings = _settings(
        mode="tools",
        tool="x",
        export_csv="out.csv",
        export_markdown="md.md",
    )
    client_instance = MagicMock()
    client_instance.get_tool_by_name = AsyncMock(
        return_value={"name": "x", "inputSchema": {"type": "object"}}
    )
    client_instance.fuzz_tool = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    reporter = _make_reporter()
    client_instance.reporter = reporter
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=reporter),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(run_fuzz_app(settings))
    reporter.export_requested_formats.assert_awaited_once_with(
        {"csv": "out.csv", "markdown": "md.md"},
        include_safety=False,
    )


def test_run_fuzz_app_exports_html_xml():
    settings = _settings(
        mode="tools",
        tool="x",
        export_html="out.html",
        export_xml="out.xml",
    )
    client_instance = MagicMock()
    client_instance.get_tool_by_name = AsyncMock(
        return_value={"name": "x", "inputSchema": {"type": "object"}}
    )
    client_instance.fuzz_tool = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    reporter = _make_reporter()
    client_instance.reporter = reporter
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=reporter),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(run_fuzz_app(settings))
    reporter.export_requested_formats.assert_awaited_once_with(
        {"html": "out.html", "xml": "out.xml"},
        include_safety=False,
    )


def test_run_fuzz_app_safety_disabled():
    settings = _settings(safety_enabled=False)
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = _make_reporter()
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter") as mock_safety,
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(run_fuzz_app(settings))
    mock_safety.assert_not_called()


def test_run_fuzz_app_tool_results_summary(monkeypatch):
    settings = _settings(mode="tools")
    client_instance = MagicMock()
    reporter = _make_reporter()
    client_instance.fuzz_all_tools = AsyncMock(
        return_value={"tool1": [{"exception": None}, {"exception": {"err": 1}}]}
    )
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = reporter
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
        patch("builtins.print"),
    ):
        asyncio.run(run_fuzz_app(settings))
    reporter.print_tool_execution_summary.assert_called_once()


def test_run_fuzz_app_returns_one_on_exception():
    settings = _settings()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(side_effect=Exception("boom"))
    client_instance.cleanup = AsyncMock()
    client_instance.reporter = _make_reporter()
    with (
        patch(
            "mcp_fuzzer.cli.bootstrap.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.cli.bootstrap.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.cli.bootstrap.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(run_fuzz_app(settings))
    assert rc == 1


class StubClient:
    def __init__(self, **_kwargs):
        self.reporter = _make_reporter()
        self._spec_checks = []

    async def fuzz_tool_both_phases(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_all_tools_both_phases(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_tool(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_all_tools(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def get_tool_by_name(self, tool_name):
        return {"name": tool_name, "inputSchema": {"type": "object"}}

    async def fuzz_protocol_type(self, *_args, **_kwargs):
        return [{"success": True}]

    async def fuzz_all_protocol_types(self, *_args, **_kwargs):
        return {"PingRequest": [{"success": True}]}

    async def fuzz_resources(self, *_args, **_kwargs):
        return {"ListResourcesRequest": [{"success": True}]}

    async def fuzz_prompts(self, *_args, **_kwargs):
        return {"ListPromptsRequest": [{"success": True}]}

    async def run_spec_suite(self, *_args, **_kwargs):
        return self._spec_checks

    async def cleanup(self):
        return None


@pytest.mark.asyncio
async def test_run_spec_guard_disabled():
    client = StubClient()
    config = {"spec_guard": False}
    await _run_spec_guard_if_enabled(client, config, reporter=None)


@pytest.mark.asyncio
async def test_run_fuzz_app_tools_phase_both(monkeypatch):
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "tools",
            "phase": "both",
            "tool": "echo",
            "runs": 1,
            "spec_guard": False,
        }
    )

    assert await fuzz_app.run_fuzz_app(settings) == 0


@pytest.mark.asyncio
async def test_run_fuzz_app_protocol_type(monkeypatch):
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "protocol",
            "protocol_type": "PingRequest",
            "runs_per_type": 1,
            "spec_guard": False,
        }
    )

    assert await fuzz_app.run_fuzz_app(settings) == 0


@pytest.mark.asyncio
async def test_run_fuzz_app_resources(monkeypatch):
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "resources",
            "runs_per_type": 1,
            "spec_guard": False,
        }
    )

    assert await fuzz_app.run_fuzz_app(settings) == 0


@pytest.mark.asyncio
async def test_run_fuzz_app_prompts(monkeypatch):
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "prompts",
            "runs_per_type": 1,
            "spec_guard": False,
        }
    )

    assert await fuzz_app.run_fuzz_app(settings) == 0


@pytest.mark.asyncio
async def test_run_fuzz_app_all_with_tool(monkeypatch):
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "all",
            "tool": "echo",
            "runs": 1,
            "runs_per_type": 1,
            "spec_guard": False,
        }
    )

    assert await fuzz_app.run_fuzz_app(settings) == 0


@pytest.mark.asyncio
async def test_run_fuzz_app_sets_schema_env(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_VERSION", raising=False)
    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "protocol",
            "protocol_type": "PingRequest",
            "spec_schema_version": "2025-11-25",
            "spec_guard": False,
        }
    )

    await fuzz_app.run_fuzz_app(settings)
    assert os.getenv("MCP_SPEC_SCHEMA_VERSION") == "2025-11-25"


@pytest.mark.asyncio
async def test_run_fuzz_app_raises_mcp_error(monkeypatch):
    class ErrorClient(StubClient):
        async def fuzz_all_tools(self, *_args, **_kwargs):
            raise MCPError("boom")

    monkeypatch.setattr(bootstrap, "MCPFuzzerClient", ErrorClient)
    monkeypatch.setattr(
        bootstrap,
        "build_driver_with_auth",
        lambda *_args, **_kwargs: MagicMock(),
    )
    settings = SimpleNamespace(
        data={
            "protocol": "stdio",
            "endpoint": "node app.js",
            "mode": "tools",
            "spec_guard": False,
        }
    )

    with pytest.raises(MCPError):
        await fuzz_app.run_fuzz_app(settings)
