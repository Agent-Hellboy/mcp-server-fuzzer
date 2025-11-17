#!/usr/bin/env python3
import asyncio
import logging
import os
import signal
import sys
from typing import Any

from rich.console import Console

from ..transport import create_transport
from ..safety_system.policy import configure_network_policy
from ..safety_system import start_system_blocking, stop_system_blocking

logger = logging.getLogger(__name__)

def create_transport_with_auth(args, client_args: dict[str, Any]):
    """Create a transport with authentication headers if available.
    
    This function handles applying auth headers to HTTP-based transports.
    For HTTP-like protocols, it extracts auth headers from the auth_manager
    and includes them in the transport initialization.
    
    Args:
        args: Arguments object with protocol, endpoint, timeout attributes
        client_args: Dictionary containing optional auth_manager
        
    Returns:
        Initialized TransportProtocol instance
        
    Raises:
        SystemExit: On transport creation error
    """
    try:
        auth_headers = None
        auth_manager = client_args.get("auth_manager")
        
        if auth_manager:
            # Prefer default provider headers, fall back to explicit tool mapping
            auth_headers = auth_manager.get_default_auth_headers()
            if not auth_headers:
                auth_headers = auth_manager.get_auth_headers_for_tool("")
            if auth_headers:
                header_keys = list(auth_headers.keys())
                logger.debug(f"Auth headers found for transport: {header_keys}")
            else:
                logger.debug("No auth headers found for default tool mapping")

        factory_kwargs = {"timeout": args.timeout}
        
        # Apply auth headers to HTTP-based protocols
        if args.protocol in ("http", "https", "streamablehttp", "sse") and auth_headers:
            factory_kwargs["auth_headers"] = auth_headers
            logger.debug(f"Adding auth headers to {args.protocol.upper()} transport")

        logger.debug(f"Creating {args.protocol.upper()} transport to {args.endpoint}")
        transport = create_transport(
            args.protocol,
            args.endpoint,
            **factory_kwargs,
        )
        if auth_headers:
            msg = "Transport created successfully with auth headers"
        else:
            msg = "Transport created successfully"
        logger.debug(msg)
        return transport
    except Exception as transport_error:
        console = Console()
        console.print(f"[bold red]Unexpected error:[/bold red] {transport_error}")
        logger.exception("Transport creation failed")
        sys.exit(1)

def prepare_inner_argv(args) -> list[str]:
    """
    Rebuild the argument vector for the inner CLI run.

    This ensures that options parsed by the outer runner (which handles things
    like retries and safety bootstrapping) are faithfully forwarded to the inner
    invocation of the CLI parser.
    """

    def _get_attr(name: str, default=None):
        """Safely get attribute values, even when args is a MagicMock."""
        if hasattr(args, "__dict__"):
            value = args.__dict__.get(name, default)
            if hasattr(value, "_mock_return_value"):
                return default
            return value
        return getattr(args, name, default)

    def _add_value(flag: str, value):
        if value is None:
            return
        argv.extend([flag, str(value)])

    def _add_bool(flag: str, attr_name: str):
        if _get_attr(attr_name, False):
            argv.append(flag)

    def _add_list(flag: str, values):
        if not values:
            return
        for val in values:
            argv.extend([flag, str(val)])

    argv: list[str] = [sys.argv[0]]

    _add_value("--mode", _get_attr("mode"))
    _add_value("--phase", _get_attr("phase", None))
    _add_value("--protocol", _get_attr("protocol"))
    _add_value("--endpoint", _get_attr("endpoint"))

    _add_value("--tool", _get_attr("tool", None))
    _add_value("--runs", _get_attr("runs", None))
    _add_value("--runs-per-type", _get_attr("runs_per_type", None))
    _add_value("--timeout", _get_attr("timeout", None))
    _add_value("--tool-timeout", _get_attr("tool_timeout", None))
    _add_value("--protocol-type", _get_attr("protocol_type", None))
    _add_value("--fs-root", _get_attr("fs_root", None))
    _add_value("--output-dir", _get_attr("output_dir", None))
    _add_value("--log-level", _get_attr("log_level", None))

    export_safety_data = _get_attr("export_safety_data", None)
    if export_safety_data is not None:
        argv.append("--export-safety-data")
        if export_safety_data:
            argv.append(str(export_safety_data))

    _add_value("--export-csv", _get_attr("export_csv", None))
    _add_value("--export-xml", _get_attr("export_xml", None))
    _add_value("--export-html", _get_attr("export_html", None))
    _add_value("--export-markdown", _get_attr("export_markdown", None))

    _add_value("--output-format", _get_attr("output_format", None))
    _add_list("--output-types", _get_attr("output_types", None))
    _add_value("--output-schema", _get_attr("output_schema", None))
    _add_value("--output-session-id", _get_attr("output_session_id", None))

    _add_bool("--verbose", "verbose")
    _add_bool("--enable-aiomonitor", "enable_aiomonitor")
    _add_bool("--output-compress", "output_compress")
    _add_bool("--enable-safety-system", "enable_safety_system")
    _add_bool("--no-safety", "no_safety")
    _add_bool("--safety-report", "safety_report")
    _add_bool("--retry-with-safety-on-interrupt", "retry_with_safety_on_interrupt")
    _add_bool("--no-network", "no_network")

    _add_list("--allow-host", _get_attr("allow_hosts", None))

    return argv

def start_safety_if_enabled(args) -> bool:
    if getattr(args, "enable_safety_system", False):
        start_system_blocking()
        return True
    return False

def stop_safety_if_started(started: bool) -> None:
    if started:
        try:
            stop_system_blocking()
        except Exception:
            pass

def execute_inner_client(args, unified_client_main, argv):
    old_argv = sys.argv
    sys.argv = argv
    should_exit = False
    try:
        if os.environ.get("PYTEST_CURRENT_TEST"):
            asyncio.run(unified_client_main())
            return

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # Check if aiomonitor is enabled
        enable_aiomonitor = getattr(args, 'enable_aiomonitor', False)
        
        if enable_aiomonitor:
            try:
                import aiomonitor
                print("AIOMonitor enabled! Connect with: telnet localhost 20101")
                print("Try commands: ps, where <task_id>, console, monitor")
                print("=" * 60)
            except ImportError:
                print(
                    "AIOMonitor requested but not installed. "
                    "Install with: pip install aiomonitor"
                )
                enable_aiomonitor = False

        # Print an immediate notice on first SIGINT/SIGTERM, then cancel tasks
        _signal_notice = {"printed": False}

        def _cancel_all_tasks():  # pragma: no cover
            if not _signal_notice["printed"]:
                try:
                    Console().print(
                        "\n[yellow]Received Ctrl+C from user; stopping now[/yellow]"
                    )
                except Exception:
                    pass
                _signal_notice["printed"] = True
            for task in asyncio.all_tasks(loop):
                task.cancel()

        if not getattr(args, "retry_with_safety_on_interrupt", False):
            try:
                loop.add_signal_handler(signal.SIGINT, _cancel_all_tasks)
                loop.add_signal_handler(signal.SIGTERM, _cancel_all_tasks)
            except NotImplementedError:
                pass
        try:
            # Configure network policy overrides
            deny = True if getattr(args, "no_network", False) else None
            extra = getattr(args, "allow_hosts", None)
            # Reset extra allowed hosts to prevent accumulation across runs
            # Reset network policy
            configure_network_policy(
                reset_allowed_hosts=True, deny_network_by_default=None
            )
            configure_network_policy(
                deny_network_by_default=deny, extra_allowed_hosts=extra
            )
            
            # Run with or without aiomonitor
            if enable_aiomonitor:
                import aiomonitor
                # Start aiomonitor with better monitoring configuration
                with aiomonitor.start_monitor(
                    loop,
                    console_enabled=True,
                    locals=True,  # Enable locals inspection
                ):
                    loop.run_until_complete(unified_client_main())
            else:
                loop.run_until_complete(unified_client_main())
        except asyncio.CancelledError:
            Console().print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            should_exit = True
        finally:
            try:
                # Cancel all remaining tasks more aggressively
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()

                # Wait for cancellation with a short timeout
                if pending:
                    gathered = asyncio.gather(*pending, return_exceptions=True)
                    try:
                        loop.run_until_complete(asyncio.wait_for(gathered, timeout=2.0))
                    except asyncio.TimeoutError:
                        # Force kill any remaining tasks
                        for t in pending:
                            if not t.done():
                                t.cancel()
            except Exception:
                pass
            loop.close()
    finally:
        sys.argv = old_argv
        if should_exit:
            raise SystemExit(130)

def run_with_retry_on_interrupt(args, unified_client_main, argv) -> None:
    try:
        execute_inner_client(args, unified_client_main, argv)
    except KeyboardInterrupt:
        console = Console()
        if (not getattr(args, "enable_safety_system", False)) and getattr(
            args, "retry_with_safety_on_interrupt", False
        ):
            console.print(
                "\n[yellow]Interrupted. Retrying once with safety system "
                "enabled...[/yellow]"
            )
            started = False
            try:
                start_system_blocking()
                started = True
            except Exception:
                pass
            try:
                execute_inner_client(args, unified_client_main, argv)
            finally:
                stop_safety_if_started(started)
        else:
            console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
            sys.exit(130)
