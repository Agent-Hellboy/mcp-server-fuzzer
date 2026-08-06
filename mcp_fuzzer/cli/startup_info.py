#!/usr/bin/env python3
"""User-facing startup output for the CLI."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Callable, Iterable, NamedTuple

from rich import box
from rich.console import Console
from rich.table import Table

from ..redaction import (
    SENSITIVE_KEY_MARKERS,
    is_sensitive_key,
    redact,
    redact_url,
)

# The redactor now lives in ``mcp_fuzzer.redaction`` so report exports share it.
# These aliases keep the previous module-local names working.
_SENSITIVE_KEY_MARKERS = SENSITIVE_KEY_MARKERS
_is_sensitive_key = is_sensitive_key
_redact_sensitive_values = redact

_AUTH_ENV_VARS = (
    "MCP_API_KEY",
    "MCP_HEADER_NAME",
    "MCP_PREFIX",
    "MCP_USERNAME",
    "MCP_PASSWORD",
    "MCP_OAUTH_TOKEN",
    "MCP_OAUTH_CLIENT_ID",
    "MCP_OAUTH_CLIENT_SECRET",
    "MCP_OAUTH_TOKEN_URL",
    "MCP_OAUTH_SCOPE",
    "MCP_CUSTOM_HEADERS",
    "MCP_TOOL_AUTH_MAPPING",
    "MCP_DEFAULT_AUTH_PROVIDER",
)


class _ArgGroup(NamedTuple):
    """A block of ``argparse`` attributes rendered as one table category."""

    category: str
    params: tuple[str, ...]
    # Flags default to False; showing them adds noise, so drop them.
    skip_false: bool = False
    format_value: Callable[[Any], str] = str


_CORE_GROUPS = (
    _ArgGroup(
        "Core",
        ("mode", "phase", "protocol_phase", "protocol", "endpoint"),
        format_value=lambda value: str(value).upper(),
    ),
)

_RUN_GROUPS = (
    _ArgGroup("Timing", ("timeout", "tool_timeout")),
    _ArgGroup(
        "Fuzzing",
        (
            "runs",
            "runs_per_type",
            "protocol_type",
            "stateful",
            "stateful_runs",
            "havoc",
            "corpus",
        ),
    ),
    _ArgGroup(
        "Safety",
        (
            "enable_safety_system",
            "no_safety",
            "fs_root",
            "no_network",
            "allow_hosts",
        ),
        skip_false=True,
    ),
)

_REPORTING_GROUPS = (
    _ArgGroup(
        "Output",
        (
            "output_dir",
            "export_csv",
            "export_xml",
            "export_html",
            "export_markdown",
            "output_format",
        ),
    ),
    _ArgGroup(
        "Process",
        (
            "watchdog_check_interval",
            "watchdog_process_timeout",
            "watchdog_extra_buffer",
            "watchdog_max_hang_time",
            "process_max_concurrency",
            "process_retry_count",
            "process_retry_delay",
        ),
    ),
    _ArgGroup(
        "Advanced",
        (
            "verbose",
            "log_level",
            "enable_aiomonitor",
            "retry_with_safety_on_interrupt",
            "validate_config",
            "check_env",
        ),
        skip_false=True,
    ),
)

# Keys worth surfacing from a merged config file, with their display labels.
_CONFIG_FILE_ROWS = (
    ("mode", "Fuzzing Mode"),
    ("protocol", "Transport Protocol"),
    ("endpoint", "Server Endpoint"),
    ("timeout", "Request Timeout"),
    ("runs", "Number of Runs"),
    ("safety_enabled", "Safety System"),
)


# Per-parameter rendering that overrides the owning group's default. The
# endpoint can carry credentials (userinfo or a token query parameter), and
# upper-casing a URL would corrupt its case-sensitive path.
_VALUE_FORMATTERS: dict[str, Callable[[Any], str]] = {
    "endpoint": lambda value: redact_url(str(value)),
}


def _label(param: str) -> str:
    return param.replace("_", " ").title()


def _load_main_config(path: str) -> Any:
    from ..config import config_mediator

    return config_mediator.load_file(path)


def _load_auth_config(path: str) -> Any:
    with open(path, "r") as handle:
        return json.load(handle)


def _print_config_file(
    console: Console,
    heading: str,
    path: str,
    load: Callable[[str], Any],
    error_label: str,
) -> None:
    """Print a configuration file's contents with sensitive values redacted."""
    console.print(f"[bold]{heading}:[/bold] {path}")
    try:
        payload = _redact_sensitive_values(load(path))
        console.print(f"[dim]{json.dumps(payload, indent=2, sort_keys=True)}[/dim]")
    except Exception as e:
        console.print(f"[red]Could not load {error_label}: {e}[/red]")
    console.print()


def _print_auth_env(console: Console) -> None:
    console.print(
        "[bold]Environment Authentication:[/bold] Using environment variables"
    )
    found_vars = [name for name in _AUTH_ENV_VARS if os.getenv(name)]
    if found_vars:
        console.print(
            f"[dim]Found environment variables: {', '.join(found_vars)}[/dim]"
        )
    else:
        console.print("[dim]No standard MCP environment variables found[/dim]")
    console.print()


def _add_arg_rows(
    table: Table, args_dict: dict[str, Any], groups: Iterable[_ArgGroup]
) -> None:
    for group in groups:
        for param in group.params:
            value = args_dict.get(param)
            if value is None or (group.skip_false and value is False):
                continue
            format_value = _VALUE_FORMATTERS.get(param, group.format_value)
            table.add_row(group.category, _label(param), format_value(value))


def _add_auth_rows(
    table: Table, args: argparse.Namespace, config: dict | None
) -> None:
    auth_config = getattr(args, "auth_config", None)
    auth_env = getattr(args, "auth_env", False)

    if auth_config:
        table.add_row("Auth", "Config File", f"Path: {auth_config}")
        auth_manager = (config or {}).get("auth_manager")
        providers = getattr(auth_manager, "auth_providers", None) or {}
        for name, provider in providers.items():
            provider_type = getattr(
                provider, "_provider_type", type(provider).__name__
            )
            table.add_row("Auth", f"Provider: {name}", f"Type: {provider_type}")

    if auth_env:
        table.add_row(
            "Auth",
            "Environment Variables",
            "Using MCP_API_KEY, MCP_OAUTH_TOKEN, MCP_USERNAME, etc.",
        )

    if not auth_config and not auth_env:
        table.add_row("Auth", "Status", "No authentication configured")


def _add_config_file_rows(
    table: Table, args: argparse.Namespace, config: dict | None
) -> None:
    config_path = getattr(args, "config", None)
    if not config_path:
        return
    table.add_row("Config", "Config File Path", config_path)
    for key, display_name in _CONFIG_FILE_ROWS:
        value = (config or {}).get(key)
        if value is not None:
            format_value = _VALUE_FORMATTERS.get(key, str)
            table.add_row("Config", display_name, format_value(value))


def _add_runtime_probe_rows(table: Table, config: dict | None) -> None:
    if config is None:
        return
    try:
        from ..runtime_probe import RuntimeProbeConfig

        probe, _ = RuntimeProbeConfig.from_mapping(config).validated_for_host(
            protocol=config.get("protocol")
        )
    except Exception:
        return
    if probe is None or not probe.enabled:
        return

    table.add_row("Runtime Probe", "Status", f"enabled ({probe.resolved_backend})")
    table.add_row("Runtime Probe", "Binary", probe.binary)
    if probe.workspace is not None:
        table.add_row("Runtime Probe", "Workspace", str(probe.workspace))
    table.add_row("Runtime Probe", "Tmpdir", str(probe.tmpdir))
    for display_name, values in (
        ("Allowed Exec", probe.exec_allow),
        ("Allowed Hosts", probe.net_allow),
    ):
        if values:
            table.add_row("Runtime Probe", display_name, ", ".join(values))


def _build_config_table(args: argparse.Namespace, config: dict | None) -> Table:
    table = Table(title="MCP Fuzzer Complete Configuration", box=box.SIMPLE_HEAD)
    table.add_column("Category", style="bold cyan", no_wrap=True)
    table.add_column("Parameter", style="cyan", no_wrap=True)
    table.add_column("Value")

    args_dict = vars(args)

    _add_arg_rows(table, args_dict, _CORE_GROUPS)

    spec_schema_version = args_dict.get("spec_schema_version")
    if spec_schema_version:
        table.add_row("Spec", "Schema Version", spec_schema_version)

    _add_auth_rows(table, args, config)
    _add_config_file_rows(table, args, config)
    _add_arg_rows(table, args_dict, _RUN_GROUPS)
    _add_runtime_probe_rows(table, config)
    _add_arg_rows(table, args_dict, _REPORTING_GROUPS)

    return table


def _print_argv_preview(console: Console, args: argparse.Namespace) -> None:
    """Show the argv the outer CLI hands to the internal fuzzer process."""
    try:
        # Imported lazily so tests can patch the builder on its own module.
        from .runtime.argv_builder import prepare_inner_argv

        built_argv = prepare_inner_argv(args)

        argv_table = Table(title="Built Command Arguments", box=box.SIMPLE_HEAD)
        argv_table.add_column("Final Command Line", style="green")
        argv_table.add_row(" ".join(built_argv))

        console.print(argv_table)
        console.print()
        console.print(
            "[dim]This argv will be passed to the internal fuzzer process.[/dim]"
        )
    except Exception as e:
        console.print(f"[red]Could not build argv preview: {e}[/red]")
    console.print()


def print_startup_info(args: argparse.Namespace, config: dict | None = None) -> None:
    console = Console()

    from .. import __version__

    console.print(
        f"[bold blue]MCP Fuzzer v{__version__} - Configuration Used:[/bold blue]"
    )
    console.print()

    # Show loaded configuration files content first
    if getattr(args, "config", None):
        _print_config_file(
            console,
            "Main Configuration File",
            args.config,
            _load_main_config,
            "config file",
        )

    if getattr(args, "auth_config", None):
        _print_config_file(
            console,
            "Authentication Configuration File",
            args.auth_config,
            _load_auth_config,
            "auth config file",
        )

    if getattr(args, "auth_env", False):
        _print_auth_env(console)

    console.print(_build_config_table(args, config))
    console.print()

    _print_argv_preview(console, args)

    console.print("[green]Starting MCP Fuzzer...[/green]")
    console.print()


__all__ = ["print_startup_info"]
