#!/usr/bin/env python3
"""Typed configuration options for subsystem dependency injection."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SafetyOptions:
    """Configuration options for the safety subsystem."""
    enabled: bool = False
    fs_root: Optional[str] = None
    no_network: bool = False
    allow_hosts: Optional[List[str]] = None
    retry_with_safety_on_interrupt: bool = False
    report: bool = False
    export_data: Optional[str] = None
    enable_system_blocking: bool = False


@dataclass(frozen=True)
class TransportOptions:
    """Configuration options for transport subsystems."""
    protocol: str = "http"
    endpoint: str = ""
    timeout: float = 30.0
    allow_hosts: Optional[List[str]] = None
    no_network: bool = False
    custom_transports: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class OutputOptions:
    """Configuration options for output/reporting subsystems."""
    output_dir: str = "reports"
    format: Optional[str] = None
    types: Optional[List[str]] = None
    schema: Optional[str] = None
    compress: bool = False
    session_id: Optional[str] = None
    export_csv: Optional[str] = None
    export_xml: Optional[str] = None
    export_html: Optional[str] = None
    export_markdown: Optional[str] = None


@dataclass(frozen=True)
class RuntimeOptions:
    """Configuration options for runtime/fuzzing behavior."""
    mode: str = "both"
    phase: Optional[str] = None
    runs: Optional[int] = None
    runs_per_type: Optional[int] = None
    tool_timeout: Optional[float] = None
    tool: Optional[str] = None
    protocol_type: Optional[str] = None
    max_concurrency: int = 5


@dataclass(frozen=True)
class AuthOptions:
    """Configuration options for authentication."""
    providers: Optional[List[Dict[str, Any]]] = None
    mappings: Optional[Dict[str, str]] = None


@dataclass(frozen=True)
class WatchdogOptions:
    """Configuration options for process watchdog."""
    check_interval: Optional[float] = None
    process_timeout: Optional[float] = None
    extra_buffer: Optional[float] = None
    max_hang_time: Optional[float] = None


@dataclass(frozen=True)
class RunPlan:
    """Structured execution plan replacing argparse.Namespace usage."""
    transport_options: TransportOptions
    safety_options: SafetyOptions
    output_options: OutputOptions
    runtime_options: RuntimeOptions
    auth_options: AuthOptions
    watchdog_options: WatchdogOptions

    # Raw config for backward compatibility
    raw_config: Dict[str, Any]

    @classmethod
    def from_config_dict(cls, config: Dict[str, Any]) -> RunPlan:
        """Create a RunPlan from a configuration dictionary."""
        # Import here to avoid circular imports
        from .builders import build_views_from_dict
        views = build_views_from_dict(config)

        return cls(
            transport_options=TransportOptions(
                protocol=getattr(views.transport, 'protocol', 'http'),
                endpoint=getattr(views.transport, 'endpoint', ''),
                timeout=getattr(views.transport, 'timeout', 30.0),
                allow_hosts=getattr(views.transport, 'allow_hosts', None),
                no_network=getattr(views.transport, 'no_network', False),
                custom_transports=config.get('custom_transports'),
            ),
            safety_options=SafetyOptions(
                enabled=getattr(views.safety, 'enabled', False),
                fs_root=getattr(views.safety, 'fs_root', None),
                no_network=getattr(views.safety, 'no_network', False),
                allow_hosts=getattr(views.safety, 'allow_hosts', None),
                retry_with_safety_on_interrupt=getattr(
                    views.safety, 'retry_with_safety_on_interrupt', False
                ),
                report=getattr(views.safety, 'report', False),
                export_data=getattr(views.safety, 'export_data', None),
                enable_system_blocking=getattr(
                    views.safety, 'enable_system_blocking', False
                ),
            ),
            output_options=OutputOptions(
                output_dir=getattr(views.output, 'output_dir', 'reports'),
                format=getattr(views.output, 'format', None),
                types=getattr(views.output, 'types', None),
                schema=getattr(views.output, 'schema', None),
                compress=getattr(views.output, 'compress', False),
                session_id=getattr(views.output, 'session_id', None),
                export_csv=config.get('export_csv'),
                export_xml=config.get('export_xml'),
                export_html=config.get('export_html'),
                export_markdown=config.get('export_markdown'),
            ),
            runtime_options=RuntimeOptions(
                mode=getattr(views.runtime, 'mode', 'both'),
                phase=getattr(views.runtime, 'phase', None),
                runs=getattr(views.runtime, 'runs', None),
                runs_per_type=getattr(views.runtime, 'runs_per_type', None),
                tool_timeout=getattr(views.runtime, 'tool_timeout', None),
                tool=getattr(views.runtime, 'tool', None),
                protocol_type=getattr(views.runtime, 'protocol_type', None),
                max_concurrency=config.get('max_concurrency', 5),
            ),
            auth_options=AuthOptions(
                providers=(config.get('auth', {}).get('providers')
                          if config.get('auth') else None),
                mappings=(config.get('auth', {}).get('mappings')
                         if config.get('auth') else None),
            ),
            watchdog_options=WatchdogOptions(
                check_interval=config.get('watchdog_check_interval'),
                process_timeout=config.get('watchdog_process_timeout'),
                extra_buffer=config.get('watchdog_extra_buffer'),
                max_hang_time=config.get('watchdog_max_hang_time'),
            ),
            raw_config=config,
        )
