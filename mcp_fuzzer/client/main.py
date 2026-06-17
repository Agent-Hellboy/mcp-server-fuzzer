#!/usr/bin/env python3
"""Unified client entrypoint used by the CLI runtime."""

from __future__ import annotations

import logging
import os
from typing import Any

from ..reports import FuzzerReporter
from ..reports.formatters.plain_summary import write_stdout_summary
from ..safety_system.safety import SafetyFilter
from ..exceptions import MCPError
from ..corpus import build_corpus_root, build_target_id, default_fs_root
from .settings import ClientSettings
from .base import MCPFuzzerClient
from .transport import TransportBuildRequest, build_driver_with_auth
from .runtime import RunContext, build_run_plan


def _build_transport_request(config: dict[str, Any]) -> TransportBuildRequest:
    return TransportBuildRequest(
        protocol=config["protocol"],
        endpoint=config["endpoint"],
        timeout=config.get("timeout", 30.0),
        transport_retries=config.get("transport_retries", 1),
        transport_retry_delay=config.get("transport_retry_delay", 0.5),
        transport_retry_backoff=config.get("transport_retry_backoff", 2.0),
        transport_retry_max_delay=config.get("transport_retry_max_delay", 5.0),
        transport_retry_jitter=config.get("transport_retry_jitter", 0.1),
        auth_manager=config.get("auth_manager"),
        safety_enabled=config.get("safety_enabled", True),
    )


def _requested_export_targets(config: dict[str, Any]) -> dict[str, str]:
    export_targets: dict[str, str] = {}
    for config_key, format_name in (
        ("export_csv", "csv"),
        ("export_xml", "xml"),
        ("export_html", "html"),
        ("export_markdown", "markdown"),
    ):
        filename = config.get(config_key)
        if filename:
            export_targets[format_name] = filename
    return export_targets


def _set_report_metadata(reporter: FuzzerReporter, config: dict[str, Any]) -> None:
    reporter.set_fuzzing_metadata(
        mode=config.get("mode", "unknown"),
        protocol=config.get("protocol", "unknown"),
        endpoint=config.get("endpoint", "unknown"),
        runs=config.get("runs", 0),
        runs_per_type=config.get("runs_per_type"),
    )


async def _run_auth_bypass_probe(config: dict[str, Any]) -> list[Any]:
    """Probe configured-but-unenforced auth by calling tools without credentials.

    Best-effort and network-active: returns ``auth_bypass`` findings for any
    protected tool that responds without an auth challenge. Never raises.
    """
    auth_manager = config.get("auth_manager")
    if auth_manager is None:
        return []
    try:
        from ..analysis import probe_auth_bypass, secured_tool_names
        from ..transport.interfaces import JsonRpcAdapter

        unauth_request = _build_transport_request({**config, "auth_manager": None})
        unauth_transport = build_driver_with_auth(unauth_request)
        adapter = JsonRpcAdapter(unauth_transport)
        try:
            tools = await adapter.get_tools()
        except Exception:
            # Discovery itself requires auth -> calls do too; no bypass.
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
        logging.debug("Auth-bypass probe skipped: %s", exc)
        return []


def _oauth_client_id(config: dict[str, Any]) -> str | None:
    auth_manager = config.get("auth_manager")
    if auth_manager is None:
        return None
    providers = getattr(auth_manager, "auth_providers", {}) or {}
    provider = providers.get("mcp_oauth")
    if provider is None:
        return None
    provider_config = getattr(provider, "config", None)
    if provider_config is None:
        return None
    return getattr(provider_config, "client_id", None)


async def _run_auth_security_audit(
    config: dict[str, Any], transport: Any
) -> list[Any]:
    """Run arXiv 2605.22333 authorization-server and MCP auth boundary checks.

    Best-effort and network-active. Never raises.
    """
    if not config.get("auth_audit"):
        return []
    if config.get("no_network"):
        return []
    probe = getattr(transport, "probe_auth_discovery", None)
    if not callable(probe):
        logging.debug("Auth audit skipped: transport lacks probe_auth_discovery")
        return []
    try:
        import httpx

        from ..analysis import (
            discover_and_audit_authorization_server,
            probe_advertised_auth_open_tools,
        )
        from ..transport.interfaces import JsonRpcAdapter

        hints = await probe()
        www_authenticate = hints.get("www_authenticate")
        auth_advertised = hints.get("status") == 401 or bool(www_authenticate)
        timeout = float(config.get("timeout", 30.0))
        findings: list[Any] = []
        with httpx.Client(timeout=timeout, follow_redirects=True) as http:
            findings.extend(
                discover_and_audit_authorization_server(
                    config["endpoint"],
                    www_authenticate=www_authenticate,
                    http=http,
                    intrusive=bool(config.get("auth_audit_intrusive")),
                    client_id=_oauth_client_id(config),
                )
            )
        if auth_advertised:
            unauth_request = _build_transport_request(
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
        return findings
    except Exception as exc:  # pragma: no cover - probe is best-effort
        logging.debug("Auth security audit skipped: %s", exc)
        return []


def _log_auth_audit_results(findings: list[Any], *, enabled: bool) -> None:
    if not enabled:
        return
    from ..analysis.auth_audit import AUTH_AUDIT_PAPER_URL, is_auth_audit_finding

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


async def unified_client_main(settings: ClientSettings) -> int:
    """Run the fuzzing workflow using merged client settings."""
    config = settings.data

    schema_version = config.get("spec_schema_version")
    if schema_version is not None:
        os.environ["MCP_SPEC_SCHEMA_VERSION"] = str(schema_version)

    logging.info(  # pragma: no cover
        "Client received config with export flags: "
        f"csv={config.get('export_csv', False)}, "
        f"xml={config.get('export_xml', False)}, "
        f"html={config.get('export_html', False)}, "
        f"md={config.get('export_markdown', False)}"
    )

    transport = build_driver_with_auth(_build_transport_request(config))

    safety_enabled = config.get("safety_enabled", True)
    safety_system = None
    if safety_enabled:
        safety_system = SafetyFilter()
        fs_root = config.get("fs_root")
        if fs_root:
            try:
                safety_system.set_fs_root(fs_root)
            except Exception as exc:  # pragma: no cover
                logging.warning(f"Failed to set filesystem root '{fs_root}': {exc}")

    reporter = None
    if "output_dir" in config:
        reporter = FuzzerReporter(
            output_dir=config["output_dir"], safety_system=safety_system
        )

    corpus_root = None
    if config.get("corpus_enabled", True):
        endpoint = config.get("endpoint") or "unknown"
        protocol = config.get("protocol", "unknown")
        target_id = build_target_id(protocol, endpoint)
        fs_root = config.get("fs_root") or str(default_fs_root())
        corpus_root = str(build_corpus_root(fs_root, target_id))

    client = MCPFuzzerClient(
        transport=transport,
        auth_manager=config.get("auth_manager"),
        tool_timeout=config.get("tool_timeout"),
        reporter=reporter,
        safety_system=safety_system,
        safety_enabled=safety_enabled,
        max_concurrency=config.get("max_concurrency", 5),
        corpus_root=corpus_root,
        havoc_mode=config.get("havoc_mode", False),
        seed=config.get("seed"),
    )
    reporter = client.reporter
    _set_report_metadata(reporter, config)

    try:
        mode = config["mode"]
        protocol_phase = config.get("protocol_phase", "realistic")
        context = RunContext(
            client=client,
            config=config,
            reporter=reporter,
            protocol_phase=protocol_phase,
        )
        try:
            plan = build_run_plan(mode, config)
        except ValueError as exc:
            logging.error("Failed to build run plan: %s", exc)
            return 1
        await plan.execute(context)
        tool_results = context.tool_results
        protocol_results = context.protocol_results

        # A tools/all run that produced no tool results could not actually
        # fuzz anything (auth required, unreachable endpoint, or no tools
        # exposed). Surface this distinctly so exit 0 is not misread.
        tools_mode = mode in ("tools", "all")
        tools_fuzzed = isinstance(tool_results, dict) and len(tool_results) > 0
        no_tools_available = tools_mode and not tools_fuzzed

        try:  # pragma: no cover
            if mode in ["tools", "all"] and tool_results:
                reporter.print_tool_execution_summary(tool_results)
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display table summary: {exc}")

        try:  # pragma: no cover
            if mode not in ("tools",) and isinstance(protocol_results, dict):
                if protocol_results:
                    reporter.print_protocol_summary(protocol_results)
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to display protocol summary tables: {exc}")

        findings_summary: dict[str, int] = {}
        tr = tool_results if isinstance(tool_results, dict) else None
        pr = protocol_results if isinstance(protocol_results, dict) else None
        try:
            from ..analysis import analyze_findings, summarize_findings
            from ..reports.crash_repro import write_crash_repros, write_findings_report

            findings = analyze_findings(tr, pr)
            if mode in ("tools", "all"):
                findings.extend(await _run_auth_bypass_probe(config))
            auth_audit_findings = await _run_auth_security_audit(config, transport)
            findings.extend(auth_audit_findings)
            _log_auth_audit_results(
                auth_audit_findings, enabled=bool(config.get("auth_audit"))
            )
            findings_summary = summarize_findings(findings)
            out_dir = config.get("output_dir") or "reports"
            crash_files = write_crash_repros(out_dir, tr, pr)
            if crash_files:
                logging.warning(
                    "Recorded %d server crash reproduction(s) in %s",
                    len(crash_files),
                    crash_files[0].parent,
                )
            if findings:
                report_path = write_findings_report(out_dir, findings)
                logging.warning(
                    "Recorded %d finding(s) across %d categor(y/ies) in %s",
                    len(findings),
                    len(findings_summary),
                    report_path,
                )
        except Exception as exc:  # pragma: no cover
            logging.warning("Failed to analyze/record findings: %s", exc)

        try:
            write_stdout_summary(
                mode=mode,
                tool_results=tr,
                protocol_results=pr,
                blocked=no_tools_available,
                findings_summary=findings_summary,
            )
        except Exception as exc:  # pragma: no cover
            logging.warning("Failed to write plain stdout summary: %s", exc)

        try:  # pragma: no cover
            output_types = config.get("output_types")
            standardized_files = await reporter.generate_standardized_report(
                output_types=output_types,
                include_safety=config.get("safety_report", False),
            )
            if standardized_files:
                logging.info(
                    f"Generated standardized reports: {list(standardized_files.keys())}"
                )
        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to generate standardized reports: {exc}")

        try:  # pragma: no cover
            export_targets = _requested_export_targets(config)
            exported_files = await reporter.export_requested_formats(
                export_targets,
                include_safety=config.get("safety_report", False),
            )
            if exported_files:
                logging.info("Exported report formats: %s", exported_files)

        except Exception as exc:  # pragma: no cover
            logging.warning(f"Failed to export additional report formats: {exc}")
            logging.exception("Export error details:")

        if no_tools_available and config.get("fail_if_no_tools", False):
            logging.warning(
                "No tools were available to fuzz; exiting non-zero due to "
                "--fail-if-no-tools"
            )
            return 2

        return 0
    except MCPError:
        raise
    except Exception as exc:
        logging.error(f"Error during fuzzing: {exc}")
        return 1
    finally:
        await client.cleanup()


__all__ = ["unified_client_main", "MCPFuzzerClient"]
