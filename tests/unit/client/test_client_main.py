"""Tests for the refactored client.main entrypoint."""

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.client import main as client_main
from mcp_fuzzer.client.main import unified_client_main
from mcp_fuzzer.client.runtime.run_plan import _run_spec_guard_if_enabled
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
    return reporter


def test_unified_client_main_tools_mode():
    settings = _settings()
    mock_transport = MagicMock()
    mock_safety = MagicMock()
    mock_reporter = MagicMock()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(
        return_value={"tool1": [{"result": "ok"}]}
    )
    client_instance.generate_standardized_reports = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()

    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=mock_transport,
        ) as mock_transport_factory,
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=mock_safety),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=mock_reporter),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(unified_client_main(settings))

    assert rc == 0
    mock_transport_factory.assert_called_once()
    assert client_instance.fuzz_all_tools.await_count == 1
    client_instance.cleanup.assert_awaited()
    mock_reporter.export_format.assert_not_called()


def test_unified_client_main_unknown_mode_logs_error_and_returns_nonzero():
    settings = _settings(mode="unknown")
    client_instance = MagicMock()
    client_instance.cleanup = AsyncMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(unified_client_main(settings))
    assert rc == 1
    client_instance.cleanup.assert_awaited()


def test_unified_client_main_sets_fs_root_when_provided():
    settings = _settings(fs_root="/tmp/safe")
    mock_safety = MagicMock()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(return_value={})
    client_instance.generate_standardized_reports = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()

    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=mock_safety),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(unified_client_main(settings))

    mock_safety.set_fs_root.assert_called_once_with("/tmp/safe")


def test_unified_client_main_protocol_and_both_modes():
    # Protocol mode without protocol_type
    settings = _settings(mode="protocol", runs_per_type=2)
    client_instance = MagicMock()
    client_instance.fuzz_all_protocol_types = AsyncMock()
    client_instance.run_spec_suite = AsyncMock(return_value=[])
    client_instance.cleanup = AsyncMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(unified_client_main(settings))
    client_instance.fuzz_all_protocol_types.assert_awaited()
    client_instance.run_spec_suite.assert_awaited()

    # Both mode with phase both and protocol_type set
    settings_both = _settings(mode="all", phase="both", protocol_type="Init")
    client_instance2 = MagicMock()
    client_instance2.fuzz_all_tools_both_phases = AsyncMock()
    client_instance2.fuzz_protocol_type = AsyncMock()
    client_instance2.run_spec_suite = AsyncMock(return_value=[])
    client_instance2.cleanup = AsyncMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance2),
    ):
        asyncio.run(unified_client_main(settings_both))
    client_instance2.fuzz_all_tools_both_phases.assert_awaited()
    client_instance2.fuzz_protocol_type.assert_awaited()
    client_instance2.run_spec_suite.assert_awaited()


def test_unified_client_main_exports_reports_and_handles_errors():
    settings = _settings(
        mode="tools",
        tool="x",
        export_csv="out.csv",
        export_markdown="md.md",
    )
    client_instance = MagicMock()
    client_instance.fuzz_tool = AsyncMock(return_value={})
    client_instance.generate_standardized_reports = AsyncMock(return_value={"f": "p"})
    client_instance.cleanup = AsyncMock()
    reporter = _make_reporter()
    client_instance.reporter = reporter
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=reporter),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(unified_client_main(settings))
    reporter.export_format.assert_any_call("csv", "out.csv")
    reporter.export_format.assert_any_call("markdown", "md.md")


def test_unified_client_main_exports_html_xml():
    settings = _settings(
        mode="tools",
        tool="x",
        export_html="out.html",
        export_xml="out.xml",
    )
    client_instance = MagicMock()
    client_instance.fuzz_tool = AsyncMock(return_value={})
    client_instance.generate_standardized_reports = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    reporter = _make_reporter()
    client_instance.reporter = reporter
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=reporter),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(unified_client_main(settings))
    reporter.export_format.assert_any_call("html", "out.html")
    reporter.export_format.assert_any_call("xml", "out.xml")


def test_unified_client_main_safety_disabled():
    settings = _settings(safety_enabled=False)
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(return_value={})
    client_instance.generate_standardized_reports = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter") as mock_safety,
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        asyncio.run(unified_client_main(settings))
    mock_safety.assert_not_called()


def test_unified_client_main_tool_results_summary(monkeypatch):
    settings = _settings(mode="tools")
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(
        return_value={"tool1": [{"exception": None}, {"exception": {"err": 1}}]}
    )
    client_instance.generate_standardized_reports = AsyncMock(return_value={})
    client_instance.cleanup = AsyncMock()
    client_instance.print_tool_summary = MagicMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
        patch("builtins.print"),
    ):
        asyncio.run(unified_client_main(settings))
    client_instance.print_tool_summary.assert_called_once()


def test_unified_client_main_returns_one_on_exception():
    settings = _settings()
    client_instance = MagicMock()
    client_instance.fuzz_all_tools = AsyncMock(side_effect=Exception("boom"))
    client_instance.cleanup = AsyncMock()
    with (
        patch(
            "mcp_fuzzer.client.main.build_driver_with_auth",
            return_value=MagicMock(),
        ),
        patch("mcp_fuzzer.client.main.SafetyFilter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.FuzzerReporter", return_value=MagicMock()),
        patch("mcp_fuzzer.client.main.MCPFuzzerClient", return_value=client_instance),
    ):
        rc = asyncio.run(unified_client_main(settings))
    assert rc == 1


class StubClient:
    def __init__(self, **_kwargs):
        self.reporter = None
        self._spec_checks = []

    async def fuzz_tool_both_phases(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_all_tools_both_phases(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_tool(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

    async def fuzz_all_tools(self, *_args, **_kwargs):
        return {"tool": [{"success": True}]}

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

    def print_protocol_summary(self, *_args, **_kwargs):
        return None

    def print_tool_summary(self, *_args, **_kwargs):
        return None

    async def generate_standardized_reports(self, *_args, **_kwargs):
        return {}


@pytest.mark.asyncio
async def test_run_spec_guard_disabled():
    client = StubClient()
    config = {"spec_guard": False}
    await _run_spec_guard_if_enabled(client, config, reporter=None)


@pytest.mark.asyncio
async def test_unified_client_main_tools_phase_both(monkeypatch):
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    assert await client_main.unified_client_main(settings) == 0


@pytest.mark.asyncio
async def test_unified_client_main_protocol_type(monkeypatch):
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    assert await client_main.unified_client_main(settings) == 0


@pytest.mark.asyncio
async def test_unified_client_main_resources(monkeypatch):
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    assert await client_main.unified_client_main(settings) == 0


@pytest.mark.asyncio
async def test_unified_client_main_prompts(monkeypatch):
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    assert await client_main.unified_client_main(settings) == 0


@pytest.mark.asyncio
async def test_unified_client_main_all_with_tool(monkeypatch):
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    assert await client_main.unified_client_main(settings) == 0


@pytest.mark.asyncio
async def test_unified_client_main_sets_schema_env(monkeypatch):
    monkeypatch.delenv("MCP_SPEC_SCHEMA_VERSION", raising=False)
    monkeypatch.setattr(client_main, "MCPFuzzerClient", StubClient)
    monkeypatch.setattr(
        client_main,
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

    await client_main.unified_client_main(settings)
    assert os.getenv("MCP_SPEC_SCHEMA_VERSION") == "2025-11-25"


@pytest.mark.asyncio
async def test_unified_client_main_raises_mcp_error(monkeypatch):
    class ErrorClient(StubClient):
        async def fuzz_all_tools(self, *_args, **_kwargs):
            raise MCPError("boom")

    monkeypatch.setattr(client_main, "MCPFuzzerClient", ErrorClient)
    monkeypatch.setattr(
        client_main,
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
        await client_main.unified_client_main(settings)
