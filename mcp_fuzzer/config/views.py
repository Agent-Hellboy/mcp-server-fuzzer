#!/usr/bin/env python3
"""Typed configuration views for subsystems."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .loader import FuzzerConfig


@dataclass(frozen=True)
class SafetySettings:
    enabled: bool
    fs_root: str | None
    no_network: bool
    allow_hosts: list[str] | None
    retry_with_safety_on_interrupt: bool
    report: bool
    export_data: str | bool | None
    enable_system_blocking: bool


@dataclass(frozen=True)
class OutputSettings:
    output_dir: str
    format: str | None
    types: list[str] | None
    schema: str | None
    compress: bool
    session_id: str | None
    export_csv: str | None
    export_xml: str | None
    export_html: str | None
    export_markdown: str | None


@dataclass(frozen=True)
class TransportSettings:
    protocol: str
    endpoint: str
    timeout: float
    allow_hosts: list[str] | None
    no_network: bool


@dataclass(frozen=True)
class RuntimeSettings:
    mode: str
    phase: str | None
    runs: int | None
    runs_per_type: int | None
    tool_timeout: float | None
    tool: str | None
    protocol_type: str | None


@dataclass(frozen=True)
class ConfigViews:
    safety: SafetySettings
    output: OutputSettings
    transport: TransportSettings
    runtime: RuntimeSettings


def build_views_from_model(model: FuzzerConfig) -> ConfigViews:
    """Build typed views from a validated FuzzerConfig model."""
    safety_enabled = (
        bool(model.safety_enabled) if model.safety_enabled is not None else False
    )
    safety_no_network = (
        bool(model.no_network) if model.no_network is not None else False
    )
    safety_allow_hosts = model.allow_hosts
    if model.safety and model.safety.local_hosts is not None:
        safety_allow_hosts = model.safety.local_hosts
    safety_view = SafetySettings(
        enabled=safety_enabled,
        fs_root=model.fs_root,
        no_network=safety_no_network
        or (model.safety.no_network if model.safety else False),
        allow_hosts=safety_allow_hosts,
        retry_with_safety_on_interrupt=bool(
            model.retry_with_safety_on_interrupt
            or (
                model.safety.retry_with_safety_on_interrupt
                if model.safety
                else False
            )
        ),
        report=bool(model.safety_report),
        export_data=model.export_safety_data,
        enable_system_blocking=bool(model.enable_safety_system),
    )

    output_view = OutputSettings(
        output_dir=(
            model.output_dir
            or (model.output.directory if model.output else "reports")
        ),
        format=model.output_format
        or (model.output.format if model.output else None),
        types=model.output_types or (model.output.types if model.output else None),
        schema=model.output_schema
        or (model.output.schema_path if model.output else None),
        compress=bool(
            model.output_compress
            or (model.output.compress if model.output else False)
        ),
        session_id=(
            model.output_session_id
            or (model.output.session_id if model.output else None)
        ),
        export_csv=model.export_csv,
        export_xml=model.export_xml,
        export_html=model.export_html,
        export_markdown=model.export_markdown,
    )

    transport_view = TransportSettings(
        protocol=model.protocol or "http",
        endpoint=model.endpoint or "",
        timeout=float(model.timeout or 30.0),
        allow_hosts=safety_view.allow_hosts,
        no_network=safety_view.no_network,
    )

    runtime_view = RuntimeSettings(
        mode=model.mode or "both",
        phase=model.phase,
        runs=model.runs,
        runs_per_type=model.runs_per_type,
        tool_timeout=model.tool_timeout,
        tool=model.tool,
        protocol_type=model.protocol_type,
    )

    return ConfigViews(
        safety=safety_view,
        output=output_view,
        transport=transport_view,
        runtime=runtime_view,
    )


def build_views_from_dict(config_data: dict[str, Any]) -> ConfigViews:
    """Validate a dict into FuzzerConfig then produce typed views."""
    from .loader import validate_config_data

    model = validate_config_data(config_data)
    return build_views_from_model(model)
