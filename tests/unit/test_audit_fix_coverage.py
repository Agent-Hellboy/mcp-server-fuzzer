#!/usr/bin/env python3
"""Coverage for v0.3.5 audit-fix branches not exercised elsewhere."""

from __future__ import annotations

import pytest

from mcp_fuzzer.cli.parser import create_argument_parser
from mcp_fuzzer.cli.validators import ValidationManager
from mcp_fuzzer.exceptions import (
    ArgumentValidationError,
    AuthConfigError,
    AuthProviderError,
)


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
        mode="tools", tool_results={}, protocol_results=None, blocked=True
    )
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "no tools available" in out


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
                {"success": False, "outcome": "transport_error", "exception": "boom"},
            ]
        }
    }
    write_stdout_summary(mode="tools", tool_results=tool_results, protocol_results=None)
    out = capsys.readouterr().out
    assert "Status: completed — 1 tool(s) fuzzed" in out
    assert "1 server-rejected input" in out
    assert "1 accepted-malformed findings" in out
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
