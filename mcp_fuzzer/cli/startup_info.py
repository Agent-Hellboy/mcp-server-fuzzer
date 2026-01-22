#!/usr/bin/env python3
"""User-facing startup output for the CLI."""

from __future__ import annotations

import argparse

from rich.console import Console


def print_startup_info(args: argparse.Namespace, config: dict | None = None) -> None:
    from rich.table import Table
    from rich import box

    console = Console()

    from .. import __version__

    console.print(
        f"[bold blue]MCP Fuzzer v{__version__} - Configuration Used:[/bold blue]"
    )
    console.print()

    # Show loaded configuration files content first
    if getattr(args, "config", None):
        console.print(f"[bold]📄 Main Configuration File:[/bold] {args.config}")
        try:
            # Load and display the config file content
            import json
            from ..client.adapters import config_mediator

            raw_config = config_mediator.load_file(args.config)
            config_json = json.dumps(raw_config, indent=2, sort_keys=True)
            console.print(f"[dim]{config_json}[/dim]")
            console.print()
        except Exception as e:
            console.print(f"[red]Could not load config file: {e}[/red]")
            console.print()

    if getattr(args, "auth_config", None):
        console.print(
            f"[bold]🔐 Authentication Configuration File:[/bold] {args.auth_config}"
        )
        try:
            # Load and display the auth config file content
            import json

            with open(args.auth_config, "r") as f:
                auth_config = json.load(f)
            auth_json = json.dumps(auth_config, indent=2, sort_keys=True)
            console.print(f"[dim]{auth_json}[/dim]")
            console.print()
        except Exception as e:
            console.print(f"[red]Could not load auth config file: {e}[/red]")
            console.print()

    if getattr(args, "auth_env", False):
        console.print(
            "[bold]🌍 Environment Authentication:[/bold] Using environment variables"
        )
        # Show which env vars are set
        import os

        env_vars = ["MCP_API_KEY", "MCP_USERNAME", "MCP_PASSWORD", "MCP_TOKEN"]
        found_vars = [var for var in env_vars if os.getenv(var)]
        if found_vars:
            console.print(
                f"[dim]Found environment variables: {', '.join(found_vars)}[/dim]"
            )
        else:
            console.print("[dim]No standard MCP environment variables found[/dim]")
        console.print()

    # Single Comprehensive Configuration Table
    config_table = Table(title="MCP Fuzzer Complete Configuration", box=box.DOUBLE)
    config_table.add_column("Category", style="bold cyan", no_wrap=True)
    config_table.add_column("Parameter", style="cyan", no_wrap=True)
    config_table.add_column("Value", style="magenta")

    args_dict = vars(args)

    # Core Configuration
    core_params = ["mode", "phase", "protocol_phase", "protocol", "endpoint"]
    for param in core_params:
        if param in args_dict and args_dict[param] is not None:
            config_table.add_row("Core", param.title(), str(args_dict[param]).upper())

    spec_schema_version = args_dict.get("spec_schema_version")
    if spec_schema_version:
        config_table.add_row("Spec", "Schema Version", spec_schema_version)

    # Authentication Configuration
    if getattr(args, "auth_config", None):
        config_table.add_row("Auth", "Config File", f"Path: {args.auth_config}")
        # Show auth config details if available in merged config
        if config and "auth_manager" in config and config["auth_manager"]:
            auth_manager = config["auth_manager"]
            if hasattr(auth_manager, "auth_providers"):
                for name, provider in auth_manager.auth_providers.items():
                    provider_type = getattr(
                        provider, "_provider_type", type(provider).__name__
                    )
                    config_table.add_row(
                        "Auth",
                        f"Provider: {name}",
                        f"Type: {provider_type}",
                    )

    if getattr(args, "auth_env", False):
        config_table.add_row(
            "Auth",
            "Environment Variables",
            "Using MCP_API_KEY, MCP_USERNAME, etc.",
        )

    if not getattr(args, "auth_config", None) and not getattr(args, "auth_env", False):
        config_table.add_row("Auth", "Status", "No authentication configured")

    # Configuration File (if --config was passed)
    if getattr(args, "config", None):
        config_table.add_row("Config", "Config File Path", args.config)
        if config:
            # Show key config parameters that were loaded from file
            config_params = [
                ("mode", "Fuzzing Mode"),
                ("protocol", "Transport Protocol"),
                ("endpoint", "Server Endpoint"),
                ("timeout", "Request Timeout"),
                ("runs", "Number of Runs"),
                ("safety_enabled", "Safety System"),
            ]
            for param_key, display_name in config_params:
                if param_key in config and config[param_key] is not None:
                    config_table.add_row("Config", display_name, str(config[param_key]))

    # Timing Settings
    timing_params = ["timeout", "tool_timeout"]
    for param in timing_params:
        if param in args_dict and args_dict[param] is not None:
            display_name = param.replace("_", " ").title()
            config_table.add_row("Timing", display_name, str(args_dict[param]))

    # Fuzzing Settings
    fuzzing_params = [
        "runs",
        "runs_per_type",
        "protocol_type",
        "stateful",
        "stateful_runs",
        "havoc",
        "corpus",
    ]
    for param in fuzzing_params:
        if param in args_dict and args_dict[param] is not None:
            display_name = param.replace("_", " ").title()
            config_table.add_row("Fuzzing", display_name, str(args_dict[param]))

    # Safety Settings
    safety_params = [
        "enable_safety_system",
        "no_safety",
        "fs_root",
        "no_network",
        "allow_hosts",
    ]
    for param in safety_params:
        if (
            param in args_dict
            and args_dict[param] is not None
            and args_dict[param] is not False
        ):
            display_name = param.replace("_", " ").title()
            config_table.add_row("Safety", display_name, str(args_dict[param]))

    # Output Settings
    output_params = [
        "output_dir",
        "export_csv",
        "export_xml",
        "export_html",
        "export_markdown",
        "output_format",
    ]
    for param in output_params:
        if param in args_dict and args_dict[param] is not None:
            display_name = param.replace("_", " ").title()
            config_table.add_row("Output", display_name, str(args_dict[param]))

    # Process Management Settings
    process_params = [
        "watchdog_check_interval",
        "watchdog_process_timeout",
        "watchdog_extra_buffer",
        "watchdog_max_hang_time",
        "process_max_concurrency",
        "process_retry_count",
        "process_retry_delay",
    ]
    for param in process_params:
        if param in args_dict and args_dict[param] is not None:
            display_name = param.replace("_", " ").title()
            config_table.add_row("Process", display_name, str(args_dict[param]))

    # Advanced Settings
    advanced_params = [
        "verbose",
        "log_level",
        "enable_aiomonitor",
        "retry_with_safety_on_interrupt",
        "validate_config",
        "check_env",
    ]
    for param in advanced_params:
        if (
            param in args_dict
            and args_dict[param] is not None
            and args_dict[param] is not False
        ):
            display_name = param.replace("_", " ").title()
            config_table.add_row("Advanced", display_name, str(args_dict[param]))

    console.print(config_table)
    console.print()

    # Built argv information (what gets passed to the fuzzer)
    try:
        from ..client.runtime.argv_builder import prepare_inner_argv

        built_argv = prepare_inner_argv(args)

        argv_table = Table(title="Built Command Arguments", box=box.ROUNDED)
        argv_table.add_column("Final Command Line", style="green")

        argv_table.add_row(" ".join(built_argv))

        console.print(argv_table)
        console.print()

        console.print(
            "[dim]This argv will be passed to the internal fuzzer process.[/dim]"
        )
        console.print()

    except Exception as e:
        console.print(f"[red]Could not build argv preview: {e}[/red]")
        console.print()

    console.print("[green]🚀 Starting MCP Fuzzer...[/green]")
    console.print()


__all__ = ["print_startup_info"]
