#!/usr/bin/env python3
"""Tests for v0.3.5 audit bug fixes (PART A + selected PART B)."""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import random
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.auth.loaders import load_auth_config
from mcp_fuzzer.cli.parser import create_argument_parser
from mcp_fuzzer.cli.validators import ValidationManager
from mcp_fuzzer.client.runtime.pipeline import ClientExecutionPipeline
from mcp_fuzzer.exceptions import AuthConfigError, ServerError
from mcp_fuzzer.fuzz_engine.mutators import ProtocolMutator, ToolMutator
from mcp_fuzzer.fuzz_engine.mutators.seed_pool import SeedPool
from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
    get_spec_protocol_fuzzer_method,
)
from mcp_fuzzer.fuzz_engine.executor.results import MetricsCalculator
from mcp_fuzzer.outcomes import FuzzOutcome, classify_protocol_run, classify_tool_run
from mcp_fuzzer.protocol_registry import FUZZABLE_PROTOCOL_TYPES
from mcp_fuzzer.reports.formatters.markdown_fmt import MarkdownFormatter
from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary
from mcp_fuzzer.reports.reporter import FuzzerReporter
from mcp_fuzzer.spec_version import is_supported_protocol_version


@pytest.fixture(autouse=True)
def _restore_config_mediator():
    """Snapshot and restore global config state so mediator-mutating tests
    do not leak ``output``/``auth`` config into later tests."""
    import copy

    from mcp_fuzzer.config import config_mediator

    snapshot = copy.deepcopy(config_mediator._config._config)
    try:
        yield
    finally:
        config_mediator._config._config = snapshot


@pytest.mark.asyncio
async def test_pipeline_single_tool_wraps_results_for_reporter():
    client = MagicMock()
    client.get_tool_by_name = AsyncMock(return_value={"name": "echo"})
    ok_run = {"success": True, "safety_blocked": False, "safety_sanitized": False}
    client.fuzz_tool = AsyncMock(return_value=[ok_run])
    pipeline = ClientExecutionPipeline(
        client, {"tool": "echo", "phase": "aggressive", "runs": 2}
    )

    results = await pipeline.fuzz_tools()

    assert "echo" in results
    assert "runs" in results["echo"]
    assert len(results["echo"]["runs"]) == 1


def test_reporter_collects_wrapped_single_tool_results():
    reporter = FuzzerReporter(output_dir="reports")
    run = {"success": True, "safety_blocked": False, "safety_sanitized": False}
    reporter.print_tool_execution_summary({"echo": {"runs": [run]}})
    assert reporter.collector.tool_results["echo"]


def test_markdown_tools_mode_omits_empty_protocol_section(tmp_path):
    formatter = MarkdownFormatter()
    report = {
        "metadata": {"mode": "tools"},
        "tool_results": {
            "echo": {
                "runs": [
                    {
                        "success": True,
                        "exception": "line1\nline2|pipe",
                        "safety_blocked": False,
                        "safety_sanitized": False,
                    }
                ]
            }
        },
        "protocol_results": {},
        "spec_summary": {"totals": {"total": 0, "failed": 0, "warned": 0, "passed": 0}},
    }
    out = tmp_path / "report.md"
    formatter.save_markdown_report(report, str(out))
    text = out.read_text()
    assert "## Tool Results" in text
    assert "## Protocol Results" not in text
    assert "## Spec Guard Summary" not in text
    assert "line1 line2\\|pipe" in text


def test_plain_stdout_summary_writes_without_tty(capsys):
    write_stdout_summary(
        mode="tools",
        tool_results={
            "echo": {
                "runs": [
                    {
                        "success": True,
                        "outcome": "server_rejected",
                        "safety_blocked": False,
                        "safety_sanitized": False,
                    }
                ]
            }
        },
        protocol_results=None,
    )
    captured = capsys.readouterr()
    assert "MCP Fuzzer Summary" in captured.out
    assert "echo:" in captured.out


def test_protocol_mode_without_protocol_type_passes_validation():
    parser = create_argument_parser()
    args = parser.parse_args(
        ["--mode", "protocol", "--endpoint", "http://localhost:8000/mcp"]
    )
    ValidationManager().validate_arguments(args)


def test_parser_prog_is_mcp_fuzzer():
    parser = create_argument_parser()
    assert parser.prog == "mcp-fuzzer"


@pytest.mark.parametrize("protocol_type", FUZZABLE_PROTOCOL_TYPES)
def test_every_fuzzable_protocol_type_has_both_phase_strategies(protocol_type):
    for phase in ("realistic", "aggressive"):
        method = get_spec_protocol_fuzzer_method(protocol_type, phase=phase)
        assert method is not None, f"{protocol_type} missing {phase} strategy"
        payload = method()
        assert isinstance(payload, dict)
        assert payload.get("jsonrpc") == "2.0"
        assert payload.get("method")


def test_outcome_semantics_server_rejection_is_success():
    exc = ServerError("rejected", context={"error": {"code": -32602, "message": "bad"}})
    success, outcome = classify_tool_run(exception=exc)
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED

    success, outcome = classify_tool_run(result={"content": []})
    assert success is False
    assert outcome == FuzzOutcome.ACCEPTED_MALFORMED


def test_protocol_outcome_semantics():
    success, outcome = classify_protocol_run(
        server_response={"error": {"code": -32602, "message": "invalid"}}
    )
    assert success is True
    assert outcome == FuzzOutcome.SERVER_REJECTED

    success, outcome = classify_protocol_run(server_response={"result": {}})
    assert success is False
    assert outcome == FuzzOutcome.ACCEPTED_MALFORMED


@pytest.mark.parametrize(
    "version", ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
)
def test_supported_protocol_versions_include_bundled_schemas(version):
    assert is_supported_protocol_version(version)


def test_seed_produces_identical_tool_mutations():
    tool = {
        "name": "echo",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
        },
    }
    pool_a = SeedPool(rng=random.Random(42))
    pool_b = SeedPool(rng=random.Random(42))
    seed = {"message": "hello"}
    pool_a.add_seed("echo", seed, signature="base")
    pool_b.add_seed("echo", seed, signature="base")
    mutator_a = ToolMutator(seed_pool=pool_a, havoc_mode=False)
    mutator_b = ToolMutator(seed_pool=pool_b, havoc_mode=False)

    async def _run(mutator: ToolMutator):
        with patch.object(ToolMutator, "_seed_ratio_for_phase", return_value=1.0):
            return await mutator.mutate(tool, phase="aggressive")

    import asyncio

    loop = asyncio.new_event_loop()
    try:
        first = loop.run_until_complete(_run(mutator_a))
        second = loop.run_until_complete(_run(mutator_b))
    finally:
        loop.close()
    assert first == second


@pytest.mark.asyncio
async def test_seed_produces_identical_protocol_mutations():
    pool_a = SeedPool(rng=random.Random(99))
    pool_b = SeedPool(rng=random.Random(99))
    mutator_a = ProtocolMutator(seed_pool=pool_a)
    mutator_b = ProtocolMutator(seed_pool=pool_b)
    with patch.object(
        ProtocolMutator, "_seed_ratio_for_phase", return_value=0.0
    ), patch(
        "mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol._definition_for",
        return_value=None,
    ):
        first = await mutator_a.mutate("PingRequest", phase="realistic")
        second = await mutator_b.mutate("PingRequest", phase="realistic")
    assert first == second


def test_auth_config_rejects_unknown_tool_mapping_provider(tmp_path):
    config_path = tmp_path / "auth.json"
    config_path.write_text(
        json.dumps(
            {
                "providers": {
                    "real": {"type": "api_key", "api_key": "secret"},
                },
                "tool_mapping": {"my_tool": "typo_name"},
            }
        )
    )
    with pytest.raises(AuthConfigError, match="unknown provider"):
        load_auth_config(str(config_path))


def test_auth_config_rejects_non_object(tmp_path):
    config_path = tmp_path / "auth.json"
    config_path.write_text(json.dumps(["not", "an", "object"]))
    with pytest.raises(AuthConfigError, match="JSON object"):
        load_auth_config(str(config_path))


def test_metrics_exclude_safety_blocked_from_exceptions():
    calc = MetricsCalculator()
    metrics = calc.calculate_tool_metrics(
        [
            {"success": False, "safety_blocked": True},
            {"success": True},
            {"success": False, "exception": "boom"},
        ]
    )
    assert metrics["exceptions"] == 1


def test_startup_info_lists_oauth_env_var(monkeypatch):
    monkeypatch.setenv("MCP_OAUTH_TOKEN", "tok")
    from mcp_fuzzer.cli.startup_info import print_startup_info

    buf = io.StringIO()
    with patch("mcp_fuzzer.cli.startup_info.Console") as mock_console:
        instance = MagicMock()
        mock_console.return_value = instance
        args = argparse.Namespace(
            config=None,
            auth_config=None,
            auth_env=True,
        )
        print_startup_info(args, {})
        printed = " ".join(str(call) for call in instance.print.call_args_list)
        assert "MCP_OAUTH_TOKEN" in printed


def test_parser_accepts_https_protocol():
    parser = create_argument_parser()
    args = parser.parse_args(
        [
            "--mode",
            "tools",
            "--endpoint",
            "https://localhost/mcp",
            "--protocol",
            "https",
        ]
    )
    assert args.protocol == "https"


def test_output_dir_none_allows_config_override():
    parser = create_argument_parser()
    args = parser.parse_args(
        ["--mode", "tools", "--endpoint", "http://localhost/mcp"]
    )
    assert args.output_dir is None


def test_nested_output_directory_applied(tmp_path):
    from mcp_fuzzer.cli.config_normalize import apply_nested_config_to_args
    from mcp_fuzzer.config import config_mediator

    config_mediator.update({"output": {"directory": str(tmp_path / "nested")}})
    parser = create_argument_parser()
    args = parser.parse_args(
        ["--mode", "tools", "--endpoint", "http://localhost/mcp"]
    )
    apply_nested_config_to_args(args, parser)
    assert args.output_dir == str(tmp_path / "nested")


def test_env_choice_validation_is_case_sensitive():
    from mcp_fuzzer.env import ValidationType

    vm = ValidationManager()
    params = {"choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]}
    assert vm._validate_env_var("INFO", ValidationType.CHOICE, params) is True
    assert vm._validate_env_var("info", ValidationType.CHOICE, params) is False


def test_yaml_auth_section_resolves_auth_manager():
    from mcp_fuzzer.client.transport.auth_port import resolve_auth_port
    from mcp_fuzzer.config import config_mediator

    config_mediator.update(
        {
            "auth": {
                "providers": [
                    {
                        "id": "api",
                        "type": "api_key",
                        "config": {"api_key": "secret"},
                    }
                ],
                "mappings": {"echo": "api"},
            }
        }
    )
    args = argparse.Namespace(auth_config=None, auth_env=False)
    manager = resolve_auth_port(args)
    assert manager is not None
    assert manager.get_auth_params_for_tool("echo") == {}


def test_safety_summary_counts_command_dangers():
    from mcp_fuzzer.safety_system.safety import SafetyFilter

    safety = SafetyFilter()
    safety.blocked_operations.append(
        {
            "tool_name": "run",
            "reason": "blocked",
            "dangerous_content": ["COMMAND in 'cmd': rm -rf /"],
        }
    )
    summary = safety.get_blocked_operations_summary()
    assert summary["dangerous_content_types"].get("commands") == 1


def test_async_executor_semaphore_rebinds_per_loop():
    from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

    executor = AsyncFuzzExecutor(max_concurrency=2)

    async def _probe():
        return id(executor._get_semaphore())

    first_id = asyncio.run(_probe())
    second_id = asyncio.run(_probe())
    assert first_id != second_id
    asyncio.run(executor.shutdown())


@pytest.mark.asyncio
async def test_async_executor_shutdown_is_idempotent():
    from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

    async with AsyncFuzzExecutor(max_concurrency=2) as executor:
        assert await executor.execute_batch([]) == {"results": [], "errors": []}
    executor = AsyncFuzzExecutor(max_concurrency=2)
    await executor.shutdown()
    await executor.shutdown()
    with pytest.raises(RuntimeError, match="shut down"):
        await executor.execute_batch([])


@pytest.mark.asyncio
async def test_tool_client_honors_max_concurrency():
    from mcp_fuzzer.client.tool_client import ToolClient

    transport = MagicMock()
    client = ToolClient(transport, max_concurrency=2)
    active = 0
    peak = 0

    async def mutate(tool, phase="aggressive"):
        return {"x": 1}

    async def call_tool(name, args, tool_timeout=None):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.05)
        active -= 1
        return {"content": []}

    client.tool_mutator.mutate = mutate
    client._rpc.call_tool = call_tool
    tool = {"name": "echo", "inputSchema": {"type": "object"}}
    await client.fuzz_tool(tool, runs=6)
    assert peak <= 2


@pytest.mark.asyncio
async def test_oauth_client_credentials_keeps_configured_token_type(monkeypatch):
    from mcp_fuzzer.auth.providers import OAuthClientCredentialsAuth

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "access_token": "tok",
                "token_type": "bearer",
                "expires_in": 3600,
            }

    monkeypatch.setattr(
        "mcp_fuzzer.auth.providers.httpx.post",
        lambda *args, **kwargs: FakeResponse(),
    )
    auth = OAuthClientCredentialsAuth(
        "https://auth.example/token",
        "id",
        "secret",
        token_type="Bearer",
    )
    headers = auth.get_auth_headers()
    assert headers["Authorization"] == "Bearer tok"


@pytest.mark.asyncio
async def test_process_supervisor_limit_overrun_raises_transport_error():
    from mcp_fuzzer.transport.controller.process_supervisor import ProcessSupervisor
    from mcp_fuzzer.exceptions import TransportError

    supervisor = ProcessSupervisor()

    class FakeReader:
        async def readline(self):
            raise asyncio.LimitOverrunError("line too long", 70000)

    with pytest.raises(TransportError, match="oversized"):
        await supervisor.read_with_cap(FakeReader(), timeout=1.0)


def test_default_shim_block_message_on_stderr(capsys):
    from mcp_fuzzer.safety_system.blocking.shims import default_shim

    with patch.object(
        default_shim.sys,
        "argv",
        ["curl", "http://example.com"],
    ), patch.object(default_shim, "LOG_FILE", ""):
        with pytest.raises(SystemExit):
            default_shim.main()
    captured = capsys.readouterr()
    assert "safety feature" in captured.err
    assert "safety feature" not in captured.out


@pytest.mark.asyncio
async def test_protocol_mutation_failure_includes_safety_keys():
    from mcp_fuzzer.client.protocol_client import ProtocolClient

    client = ProtocolClient(MagicMock(), max_concurrency=1)
    client.protocol_mutator.mutate = AsyncMock(
        side_effect=RuntimeError("mutate failed")
    )

    result = await client._process_single_protocol_fuzz(
        "PingRequest", 0, 1, phase="realistic"
    )

    assert result["success"] is False
    assert result["safety_blocked"] is False
    assert result["safety_sanitized"] is False
    assert "mutate failed" in result["exception"]


@pytest.mark.asyncio
async def test_protocol_client_honors_max_concurrency():
    from mcp_fuzzer.client.protocol_client import ProtocolClient

    client = ProtocolClient(MagicMock(), max_concurrency=2)
    active = 0
    peak = 0

    async def process_single(protocol_type, run_index, total_runs, phase="realistic"):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.05)
        active -= 1
        return {
            "success": True,
            "safety_blocked": False,
            "safety_sanitized": False,
            "fuzz_data": {},
        }

    client._process_single_protocol_fuzz = process_single
    client._append_follow_up_results = AsyncMock()
    await client.fuzz_protocol_type("PingRequest", runs=6)
    assert peak <= 2


def test_load_auth_config_accepts_mappings_alias(tmp_path):
    config_path = tmp_path / "auth.json"
    config_path.write_text(
        json.dumps(
            {
                "providers": {
                    "api": {"type": "api_key", "api_key": "secret"},
                },
                "mappings": {"echo": "api"},
            }
        )
    )
    manager = load_auth_config(str(config_path))
    assert manager is not None

