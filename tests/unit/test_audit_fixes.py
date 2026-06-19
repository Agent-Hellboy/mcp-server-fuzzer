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
from mcp_fuzzer.orchestrator.pipeline import ClientExecutionPipeline
from mcp_fuzzer.exceptions import (
    ArgumentValidationError,
    AuthConfigError,
    AuthProviderError,
    ServerError,
)
from mcp_fuzzer.fuzz_engine.mutators import ProtocolMutator, ToolMutator
from mcp_fuzzer.fuzz_engine.mutators.seed_pool import SeedPool
from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
    get_spec_protocol_fuzzer_method,
)
from mcp_fuzzer.fuzz_engine.executor.results import MetricsCalculator
from mcp_fuzzer.client.outcomes import (
    FuzzOutcome,
    classify_protocol_run,
    classify_tool_run,
)
from mcp_fuzzer.protocol_registry import FUZZABLE_PROTOCOL_TYPES
from mcp_fuzzer.reports.formatters.markdown_fmt import MarkdownFormatter
from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary
from mcp_fuzzer.reports.reporter import FuzzerReporter
from mcp_fuzzer.spec_guard.spec_version import is_supported_protocol_version


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
    from mcp_fuzzer.config.env import ValidationType

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


# ---------------------------------------------------------------------------
# Merged from test_audit_fix_coverage.py
# Coverage for v0.3.5 audit-fix branches not exercised elsewhere.
# ---------------------------------------------------------------------------


def _protocol_args(protocol_type: str):
    parser = create_argument_parser()
    return parser.parse_args(
        [
            "--mode",
            "protocol",
            "--endpoint",
            "http://localhost:8000/mcp",
            "--protocol-type",
            protocol_type,
        ]
    )


def test_unsupported_protocol_type_raises():
    with pytest.raises(ArgumentValidationError, match="Unsupported protocol type"):
        ValidationManager().validate_arguments(_protocol_args("TotallyBogusRequest"))


def test_empty_protocol_type_tokens_raise():
    with pytest.raises(ArgumentValidationError, match="cannot be empty"):
        ValidationManager().validate_arguments(_protocol_args(" | "))


# --- yaml_loader error branches ------------------------------------------


def test_yaml_custom_provider_missing_headers():
    from mcp_fuzzer.auth.yaml_loader import build_auth_from_yaml_section

    with pytest.raises(AuthProviderError, match="missing.*headers"):
        build_auth_from_yaml_section(
            {"providers": [{"id": "c", "type": "custom"}]}
        )


def test_yaml_provider_missing_required_field_wrapped():
    from mcp_fuzzer.auth.yaml_loader import build_auth_from_yaml_section

    # api_key provider without 'api_key' -> KeyError wrapped as AuthProviderError.
    with pytest.raises(AuthProviderError, match="Error configuring auth provider"):
        build_auth_from_yaml_section(
            {"providers": [{"id": "a", "type": "api_key", "config": {}}]}
        )


def test_yaml_dict_providers_without_tool_mapping():
    from mcp_fuzzer.auth.yaml_loader import build_auth_from_yaml_section

    manager = build_auth_from_yaml_section(
        {"providers": {"api": {"type": "api_key", "api_key": "k"}}}
    )
    assert "api" in manager.auth_providers
    assert manager.tool_auth_mapping == {}


def test_yaml_unknown_default_provider_with_dict_providers():
    from mcp_fuzzer.auth.yaml_loader import build_auth_from_yaml_section

    with pytest.raises(AuthConfigError):
        build_auth_from_yaml_section(
            {
                "providers": {"api": {"type": "api_key", "api_key": "k"}},
                "default_provider": "missing",
            }
        )


# --- AsyncFuzzExecutor post-shutdown guards -------------------------------


@pytest.mark.asyncio
async def test_executor_execute_single_after_shutdown_raises():
    from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

    executor = AsyncFuzzExecutor(max_concurrency=2)
    await executor.shutdown()
    with pytest.raises(RuntimeError, match="shut down"):
        await executor._execute_single(lambda: None, (), {})


@pytest.mark.asyncio
async def test_executor_run_hypothesis_strategy_after_shutdown_raises():
    from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

    executor = AsyncFuzzExecutor(max_concurrency=2)
    await executor.shutdown()

    class _Strategy:
        def example(self):
            return 1

    with pytest.raises(RuntimeError, match="shut down"):
        await executor.run_hypothesis_strategy(_Strategy())


# --- spec_protocol fallback / schema-param branches -----------------------


def test_prepare_schema_params_unknown_type_returns_overrides():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
        _prepare_schema_params,
    )

    overrides = {"x": 1}
    assert (
        _prepare_schema_params("NotARealType", "realistic", overrides, None)
        == overrides
    )


def test_build_fallback_request_unknown_type_returns_none():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
        _build_fallback_request,
    )

    assert _build_fallback_request("NotARealType", "realistic") is None


def test_build_fallback_request_aggressive_has_malicious_params():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.spec_protocol import (
        _build_fallback_request,
    )

    envelope = _build_fallback_request("PingRequest", "aggressive")
    assert envelope is not None
    assert envelope["method"] == "ping"
    assert "value" in envelope["params"]


# --- schema_parser allOf enum intersection / required props ---------------


def test_merge_allof_enum_intersection():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import _merge_allOf

    merged = _merge_allOf(
        [
            {"type": "string", "enum": ["a", "b", "c"]},
            {"enum": ["b", "c", "d"]},
        ]
    )
    assert sorted(merged["enum"]) == ["b", "c"]


def test_merge_allof_empty_enum_intersection_marks_contradiction():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import _merge_allOf

    merged = _merge_allOf([{"enum": ["a"]}, {"enum": ["b"]}])
    assert merged.get("_schema_contradiction") == "empty_enum_intersection"


def test_required_property_missing_from_properties_is_emitted():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
        make_fuzz_strategy_from_jsonschema,
    )

    schema = {
        "type": "object",
        "properties": {"present": {"type": "string"}},
        "required": ["present", "absent"],
    }
    result = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")
    assert "present" in result
    assert "absent" in result


def test_contradictory_allof_type_returns_marker():
    from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
        make_fuzz_strategy_from_jsonschema,
    )

    schema = {"allOf": [{"type": "string"}, {"type": "integer"}]}
    result = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
    assert result == {"__schema_contradiction__": "empty_type_intersection"}


# --- stdio transport serializes concurrent exchanges ----------------------


@pytest.mark.asyncio
async def test_stdio_send_request_serializes_concurrent_exchanges():
    """Concurrent send_request calls must not overlap on the single stdout
    stream (regression for the readuntil() concurrency bug)."""
    import asyncio

    from mcp_fuzzer.transport.drivers.stdio_driver import StdioDriver

    transport = StdioDriver("dummy-cmd", timeout=5)
    transport._mcp_initialized = True  # skip the initialize handshake

    sent_ids: list[str] = []
    active = 0
    peak = 0

    async def fake_send(message):
        sent_ids.append(message["id"])

    async def fake_receive():
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.01)
            return {"jsonrpc": "2.0", "id": sent_ids[-1], "result": {"ok": True}}
        finally:
            active -= 1

    transport._send_message = fake_send
    transport._receive_message = fake_receive

    results = await asyncio.gather(
        *(transport.send_request("tools/list") for _ in range(6))
    )

    assert all(r == {"ok": True} for r in results)
    assert peak == 1  # the io lock serialized every exchange


# --- clearer "no tools" outcome + findings labels ------------------------


def test_stdout_summary_blocked_status(capsys):
    from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary

    write_stdout_summary(
        mode="tools",
        tool_results={},
        protocol_results=None,
        blocked=True,
        tool_discovery={
            "failure": "connection_failed",
            "detail": "Connection failed while contacting server",
        },
    )
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "connection_failed" in out
    assert "Connection failed while contacting server" in out


def test_stdout_summary_completed_with_outcome_buckets(capsys):
    from mcp_fuzzer.reports.formatters.plain_summary import write_stdout_summary

    tool_results = {
        "echo": {
            "runs": [
                {"success": True, "outcome": "server_rejected"},
                {
                    "success": False,
                    "outcome": "accepted_malformed",
                    "accepted_malformed": True,
                },
                {"success": False, "outcome": "transport_error"},
                {"success": False, "outcome": "transport_error", "exception": "boom"},
            ]
        }
    }
    write_stdout_summary(mode="tools", tool_results=tool_results, protocol_results=None)
    out = capsys.readouterr().out
    assert "Status: completed — 1 tool(s) fuzzed" in out
    assert "1 server-rejected input" in out
    assert "1 accepted-malformed findings" in out
    # transport_error without exception counts as anomaly; exception runs do not
    assert "1 transport/protocol anomalies" in out


def test_fail_if_no_tools_flag_parses_and_merges():
    from mcp_fuzzer.cli.config_merge import build_cli_config
    from mcp_fuzzer.config import config_mediator

    parser = create_argument_parser()
    args = parser.parse_args(
        ["--mode", "tools", "--endpoint", "http://x/mcp", "--fail-if-no-tools"]
    )
    assert args.fail_if_no_tools is True

    import copy

    snapshot = copy.deepcopy(config_mediator._config._config)
    try:
        cfg = build_cli_config(args)
        assert cfg.merged["fail_if_no_tools"] is True
    finally:
        config_mediator._config._config = snapshot

