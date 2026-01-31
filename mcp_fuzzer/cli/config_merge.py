#!/usr/bin/env python3
"""Configuration merging between CLI args and config files."""

from __future__ import annotations

import argparse
import logging
from typing import Any

from ..exceptions import ConfigFileError
from ..client.adapters import config_mediator
from ..client.settings import CliConfig
from ..client.transport.auth_port import resolve_auth_port
from .parser import create_argument_parser


def _transfer_config_to_args(args: argparse.Namespace) -> None:
    defaults_parser = create_argument_parser()
    mapping = [
        ("endpoint", "endpoint"),
        ("protocol", "protocol"),
        ("mode", "mode"),
        ("phase", "phase"),
        ("protocol_phase", "protocol_phase"),
        ("timeout", "timeout"),
        ("transport_retries", "transport_retries"),
        ("transport_retry_delay", "transport_retry_delay"),
        ("transport_retry_backoff", "transport_retry_backoff"),
        ("transport_retry_max_delay", "transport_retry_max_delay"),
        ("transport_retry_jitter", "transport_retry_jitter"),
        ("tool_timeout", "tool_timeout"),
        ("tool", "tool"),
        ("runs", "runs"),
        ("runs_per_type", "runs_per_type"),
        ("protocol_type", "protocol_type"),
        ("stateful", "stateful"),
        ("stateful_runs", "stateful_runs"),
        ("havoc_mode", "havoc"),
        ("corpus_enabled", "corpus"),
        ("spec_guard", "spec_guard"),
        ("spec_resource_uri", "spec_resource_uri"),
        ("spec_prompt_name", "spec_prompt_name"),
        ("spec_prompt_args", "spec_prompt_args"),
        ("spec_schema_version", "spec_schema_version"),
        ("fs_root", "fs_root"),
        ("enable_safety_system", "enable_safety_system"),
        ("safety_report", "safety_report"),
        ("export_safety_data", "export_safety_data"),
        ("output_dir", "output_dir"),
        ("output_format", "output_format"),
        ("output_types", "output_types"),
        ("output_schema", "output_schema"),
        ("output_compress", "output_compress"),
        ("output_session_id", "output_session_id"),
        ("export_csv", "export_csv"),
        ("export_xml", "export_xml"),
        ("export_html", "export_html"),
        ("export_markdown", "export_markdown"),
        ("log_level", "log_level"),
        ("verbose", "verbose"),
        ("no_network", "no_network"),
        ("allow_hosts", "allow_hosts"),
        ("watchdog_check_interval", "watchdog_check_interval"),
        ("watchdog_process_timeout", "watchdog_process_timeout"),
        ("watchdog_extra_buffer", "watchdog_extra_buffer"),
        ("watchdog_max_hang_time", "watchdog_max_hang_time"),
        ("process_max_concurrency", "process_max_concurrency"),
        ("max_concurrency", "max_concurrency"),
        ("process_retry_count", "process_retry_count"),
        ("process_retry_delay", "process_retry_delay"),
        ("enable_aiomonitor", "enable_aiomonitor"),
        ("validate_config", "validate_config"),
        ("check_env", "check_env"),
        ("retry_with_safety_on_interrupt", "retry_with_safety_on_interrupt"),
    ]

    for config_key, args_key in mapping:
        config_value = config_mediator.get(config_key)
        default_value = defaults_parser.get_default(args_key)
        if default_value is argparse.SUPPRESS:  # pragma: no cover
            default_value = None
        args_value = getattr(args, args_key, default_value)
        if config_value is not None and args_value == default_value:
            setattr(args, args_key, config_value)


def build_cli_config(args: argparse.Namespace) -> CliConfig:
    """Merge CLI args, config files, and resolved auth."""
    if args.config:
        try:
            loaded = config_mediator.load_file(args.config)
            config_mediator.update(loaded)
        except Exception as exc:
            raise ConfigFileError(
                f"Failed to load configuration file '{args.config}': {exc}"
            ) from exc
    else:
        # apply_file() returns False if config loading fails (doesn't raise)
        if not config_mediator.apply_file():
            logging.debug(
                "Default configuration file not found or failed to load "
                "(this is normal if no config file exists)"
            )

    _transfer_config_to_args(args)
    auth_manager = resolve_auth_port(args)

    merged: dict[str, Any] = {
        "mode": args.mode,
        "phase": args.phase,
        "protocol_phase": getattr(args, "protocol_phase", "realistic"),
        "protocol": args.protocol,
        "endpoint": args.endpoint,
        "timeout": args.timeout,
        "transport_retries": getattr(args, "transport_retries", 1),
        "transport_retry_delay": getattr(args, "transport_retry_delay", 0.5),
        "transport_retry_backoff": getattr(args, "transport_retry_backoff", 2.0),
        "transport_retry_max_delay": getattr(args, "transport_retry_max_delay", 5.0),
        "transport_retry_jitter": getattr(args, "transport_retry_jitter", 0.1),
        "tool_timeout": getattr(args, "tool_timeout", None),
        "tool": getattr(args, "tool", None),
        "fs_root": getattr(args, "fs_root", None),
        "verbose": args.verbose,
        "runs": args.runs,
        "runs_per_type": args.runs_per_type,
        "protocol_type": args.protocol_type,
        "stateful": getattr(args, "stateful", False),
        "stateful_runs": getattr(args, "stateful_runs", 5),
        "havoc_mode": getattr(args, "havoc", False),
        "corpus_enabled": getattr(args, "corpus", True),
        "spec_guard": getattr(args, "spec_guard", True),
        "spec_resource_uri": getattr(args, "spec_resource_uri", None),
        "spec_prompt_name": getattr(args, "spec_prompt_name", None),
        "spec_prompt_args": getattr(args, "spec_prompt_args", None),
        "spec_schema_version": getattr(args, "spec_schema_version", None),
        "safety_enabled": not getattr(args, "no_safety", False),
        "enable_safety_system": getattr(args, "enable_safety_system", False),
        "safety_report": getattr(args, "safety_report", False),
        "export_safety_data": getattr(args, "export_safety_data", None),
        "output_dir": getattr(args, "output_dir", "reports"),
        "retry_with_safety_on_interrupt": getattr(
            args, "retry_with_safety_on_interrupt", False
        ),
        "log_level": getattr(args, "log_level", None),
        "no_network": getattr(args, "no_network", False),
        "allow_hosts": getattr(args, "allow_hosts", None),
        "validate_config": getattr(args, "validate_config", None),
        "check_env": getattr(args, "check_env", False),
        "export_csv": getattr(args, "export_csv", None),
        "export_xml": getattr(args, "export_xml", None),
        "export_html": getattr(args, "export_html", None),
        "export_markdown": getattr(args, "export_markdown", None),
        "watchdog_check_interval": getattr(args, "watchdog_check_interval", 1.0),
        "watchdog_process_timeout": getattr(args, "watchdog_process_timeout", 30.0),
        "watchdog_extra_buffer": getattr(args, "watchdog_extra_buffer", 5.0),
        "watchdog_max_hang_time": getattr(args, "watchdog_max_hang_time", 60.0),
        "process_max_concurrency": getattr(args, "process_max_concurrency", 5),
        "max_concurrency": getattr(args, "max_concurrency", 5),
        "process_retry_count": getattr(args, "process_retry_count", 1),
        "process_retry_delay": getattr(args, "process_retry_delay", 1.0),
        "output_format": getattr(args, "output_format", "json"),
        "output_types": getattr(args, "output_types", None),
        "output_schema": getattr(args, "output_schema", None),
        "output_compress": getattr(args, "output_compress", False),
        "output_session_id": getattr(args, "output_session_id", None),
        "enable_aiomonitor": getattr(args, "enable_aiomonitor", False),
        "auth_manager": auth_manager,
    }

    config_mediator.update(merged)
    return CliConfig(args=args, merged=merged)


__all__ = ["build_cli_config"]
