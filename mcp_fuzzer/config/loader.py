#!/usr/bin/env python3
"""Simple configuration loader: env → file → overrides, with Pydantic validation."""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

from ..exceptions import ConfigFileError

logger = logging.getLogger(__name__)


# --- Pydantic models ----------------------------------------------------

class SafetyConfig(BaseModel):
    class Config:
        extra = "forbid"

    enabled: bool | None = None
    local_hosts: list[str] | None = None
    no_network: bool | None = None
    header_denylist: list[str] | None = None
    proxy_env_denylist: list[str] | None = None
    env_allowlist: list[str] | None = None
    retry_with_safety_on_interrupt: bool | None = None


class OutputConfig(BaseModel):
    class Config:
        extra = "forbid"
        allow_population_by_field_name = True

    format: str | None = None
    directory: str | None = None
    compress: bool | None = None
    types: list[str] | None = None
    schema_path: str | None = Field(default=None, alias="schema")
    retention: dict[str, Any] | None = None
    session_id: str | None = Field(default=None, alias="session_id")


class WatchdogConfig(BaseModel):
    class Config:
        extra = "forbid"

    check_interval: float | None = None
    process_timeout: float | None = None
    extra_buffer: float | None = None
    max_hang_time: float | None = None


class RuntimeConfig(BaseModel):
    class Config:
        extra = "forbid"

    max_concurrency: int | None = None
    retry_count: int | None = None
    retry_delay: float | None = None


class AuthProviderConfig(BaseModel):
    class Config:
        extra = "forbid"

    type: str
    id: str
    config: dict[str, Any] | None = None


class AuthConfig(BaseModel):
    class Config:
        extra = "forbid"

    providers: list[AuthProviderConfig] | None = None
    mappings: dict[str, str] | None = None


class FuzzerConfig(BaseModel):
    class Config:
        extra = "forbid"
        allow_population_by_field_name = True

    # Core
    timeout: float | None = None
    tool_timeout: float | None = None
    tool: str | None = None
    log_level: str | None = None
    verbose: bool | None = None
    safety_enabled: bool | None = None
    fs_root: str | None = None
    http_timeout: float | None = None
    sse_timeout: float | None = None
    stdio_timeout: float | None = None
    mode: str | None = None
    phase: str | None = None
    protocol: str | None = None
    endpoint: str | None = None
    runs: int | None = None
    runs_per_type: int | None = None
    protocol_type: str | None = None
    no_network: bool | None = None
    allow_hosts: list[str] | None = None
    max_concurrency: int | None = None
    auth: AuthConfig | None = None
    custom_transports: dict[str, Any] | None = None
    safety: SafetyConfig | None = None
    output: OutputConfig | None = None
    runtime: RuntimeConfig | None = None
    watchdog: WatchdogConfig | None = None
    # Toggling safety/system behavior
    enable_safety_system: bool | None = None
    safety_report: bool | None = None
    export_safety_data: str | bool | None = None
    retry_with_safety_on_interrupt: bool | None = None
    enable_aiomonitor: bool | None = None
    no_safety: bool | None = None
    # Output shortcuts
    output_dir: str | None = None
    output_format: str | None = None
    output_types: list[str] | None = None
    output_schema: str | None = None
    output_compress: bool | None = None
    output_session_id: str | None = None
    export_csv: str | None = None
    export_xml: str | None = None
    export_html: str | None = None
    export_markdown: str | None = None
    # Network safety shortcuts
    allow_host: str | list[str] | None = None
    # Watchdog/process settings
    watchdog_check_interval: float | None = None
    watchdog_process_timeout: float | None = None
    watchdog_extra_buffer: float | None = None
    watchdog_max_hang_time: float | None = None
    process_max_concurrency: int | None = None
    process_retry_count: int | None = None
    process_retry_delay: float | None = None
    # Utility flags
    validate_config: str | None = None
    check_env: bool | None = None
    runs_per_phase: int | None = None
    # Docs structured helper blocks
    global_: dict[str, Any] | None = Field(default=None, alias="global")
    transports: dict[str, Any] | None = None


# --- Helpers -------------------------------------------------------------

def load_env_defaults() -> dict[str, Any]:
    """Load configuration values from environment variables."""
    def _get_float(key: str, default: float) -> float:
        try:
            return float(os.getenv(key, str(default)))
        except (TypeError, ValueError):
            return default

    def _get_bool(key: str, default: bool = False) -> bool:
        val = os.getenv(key)
        if val is None:
            return default
        return val.strip().lower() in {"1", "true", "yes", "on"}

    return {
        "timeout": _get_float("MCP_FUZZER_TIMEOUT", 30.0),
        "log_level": os.getenv("MCP_FUZZER_LOG_LEVEL", "INFO"),
        "safety_enabled": _get_bool("MCP_FUZZER_SAFETY_ENABLED", False),
        "fs_root": os.getenv("MCP_FUZZER_FS_ROOT", os.path.expanduser("~/.mcp_fuzzer")),
        "http_timeout": _get_float("MCP_FUZZER_HTTP_TIMEOUT", 30.0),
        "sse_timeout": _get_float("MCP_FUZZER_SSE_TIMEOUT", 30.0),
        "stdio_timeout": _get_float("MCP_FUZZER_STDIO_TIMEOUT", 30.0),
    }


def find_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> str | None:
    """Find a configuration file in the given paths."""
    if config_path and os.path.isfile(config_path):
        return config_path

    search_paths = search_paths or [
        os.getcwd(),
        str(Path.home() / ".config" / "mcp-fuzzer"),
    ]
    file_names = file_names or ["mcp-fuzzer.yml", "mcp-fuzzer.yaml"]

    for path in search_paths:
        if not os.path.isdir(path):
            continue
        for name in file_names:
            file_path = os.path.join(path, name)
            if os.path.isfile(file_path):
                return file_path
    return None


def load_config_file(file_path: str) -> dict[str, Any]:
    """Load configuration from a YAML file."""
    if not os.path.isfile(file_path):
        raise ConfigFileError(f"Configuration file not found: {file_path}")
    if not file_path.endswith((".yml", ".yaml")):
        raise ConfigFileError(
            f"Unsupported configuration file format: {file_path}. "
            "Only YAML files with .yml or .yaml extensions are supported."
        )
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigFileError(
            f"Error parsing YAML configuration file {file_path}: {str(e)}"
        )
    except PermissionError:
        raise ConfigFileError(
            f"Permission denied when reading configuration file: {file_path}"
        )
    except Exception as e:
        raise ConfigFileError(
            f"Unexpected error reading configuration file {file_path}: {str(e)}"
        )


def normalize_config_data(config_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize nested configuration structures into the flat keys the app uses."""
    if not isinstance(config_data, dict):
        raise ConfigFileError("Configuration root must be a mapping")

    normalized = dict(config_data)

    global_section = config_data.get("global")
    if isinstance(global_section, dict):
        for key, value in global_section.items():
            normalized.setdefault(key, value)

    # Safety block -> flattened keys
    safety = config_data.get("safety")
    if isinstance(safety, dict):
        mapping = {
            "enabled": "safety_enabled",
            "fs_root": "fs_root",
            "no_network": "no_network",
            "local_hosts": "allow_hosts",
            "retry_with_safety_on_interrupt": "retry_with_safety_on_interrupt",
        }
        for src, dest in mapping.items():
            if src in safety:
                normalized.setdefault(dest, safety[src])
        normalized["safety"] = safety

    # Watchdog block -> flattened keys
    watchdog = config_data.get("watchdog")
    if isinstance(watchdog, dict):
        mapping = {
            "check_interval": "watchdog_check_interval",
            "process_timeout": "watchdog_process_timeout",
            "extra_buffer": "watchdog_extra_buffer",
            "max_hang_time": "watchdog_max_hang_time",
        }
        for src, dest in mapping.items():
            if src in watchdog:
                normalized.setdefault(dest, watchdog[src])
        normalized["watchdog"] = watchdog

    # Output block -> flattened keys
    output = config_data.get("output")
    if isinstance(output, dict):
        mapping = {
            "directory": "output_dir",
            "format": "output_format",
            "types": "output_types",
            "schema": "output_schema",
            "compress": "output_compress",
            "session_id": "output_session_id",
        }
        for src, dest in mapping.items():
            if src in output:
                normalized.setdefault(dest, output[src])
        normalized["output"] = output

    # Runtime/process block -> flattened keys
    runtime = config_data.get("runtime")
    if isinstance(runtime, dict):
        mapping = {
            "max_concurrency": "process_max_concurrency",
            "retry_count": "process_retry_count",
            "retry_delay": "process_retry_delay",
        }
        for src, dest in mapping.items():
            if src in runtime:
                normalized.setdefault(dest, runtime[src])
        normalized["runtime"] = runtime

    return normalized


def validate_config_data(config_data: dict[str, Any]) -> FuzzerConfig:
    """Validate configuration data with the Pydantic model and return it."""
    try:
        return FuzzerConfig.parse_obj(config_data)
    except ValidationError as exc:
        messages = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "root"
            messages.append(f"{loc}: {err['msg']}")
        raise ConfigFileError("Invalid configuration:\n" + "\n".join(messages))


def load_config_model(config_data: dict[str, Any]) -> FuzzerConfig:
    """Compatibility wrapper around validate_config_data."""
    return validate_config_data(config_data)


def model_to_config_dict(model: FuzzerConfig) -> dict[str, Any]:
    """Dump a Pydantic model to a dict with aliases and no Nones."""
    return model.dict(by_alias=True, exclude_none=True)


def load_config(
    config_path: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], FuzzerConfig]:
    """Load configuration: env -> file -> CLI overrides. Returns dict and model."""
    merged: dict[str, Any] = load_env_defaults()

    file_path = find_config_file(config_path)
    if file_path:
        file_data = load_config_file(file_path)
        merged.update(normalize_config_data(file_data))

    if cli_overrides:
        for key, value in cli_overrides.items():
            if value is not None:
                merged[key] = value

    model = validate_config_data(merged)
    # Apply defaults that validation may set (e.g., alias resolution)
    merged = model.dict(by_alias=True, exclude_none=True)
    return merged, model


def apply_config_file(
    config_path: str | None = None,
    search_paths: list[str] | None = None,
    file_names: list[str] | None = None,
) -> bool:
    """Find, load, normalize, validate, and apply configuration to global store."""
    from .manager import config as global_config

    try:
        path = find_config_file(config_path, search_paths, file_names)
        if not path:
            logger.debug("No configuration file found")
            return False
        raw = load_config_file(path)
        normalized = normalize_config_data(raw)
        model = validate_config_data(normalized)
        data = model.dict(by_alias=True, exclude_none=True)
        load_custom_transports(data)
        global_config.clear()
        global_config.update(data)
        return True
    except Exception as e:
        logger.warning(f"Failed to apply config file: {e}")
        return False


def get_config_schema() -> dict[str, Any]:
    """Return a JSON-schema-like dict for documentation."""
    props: dict[str, Any] = {}
    for name, field in FuzzerConfig.__fields__.items():
        key = field.alias or name
        props[key] = {}
    return {"type": "object", "additionalProperties": False, "properties": props}


# Custom transports loading during pipeline
def load_custom_transports(config_data: dict[str, Any]) -> None:
    """Import and register custom transports defined in config."""
    custom_transports = config_data.get("custom_transports", {})
    if not custom_transports:
        return

    from ..transport.custom import register_custom_transport
    from ..transport.base import TransportProtocol
    import importlib

    for name, cfg in custom_transports.items():
        try:
            module = importlib.import_module(cfg["module"])
            klass = getattr(module, cfg["class"])
        except Exception as exc:
            raise ConfigFileError(
                f"Failed to load custom transport '{name}': {exc}"
            ) from exc
        if not isinstance(klass, type) or not issubclass(klass, TransportProtocol):
            raise ConfigFileError(
                f"{cfg['module']}.{cfg['class']} must subclass TransportProtocol"
            )
        description = cfg.get("description", "")
        schema = cfg.get("config_schema")
        factory_fn = None
        factory_path = cfg.get("factory")
        if factory_path:
            mod_path, attr = factory_path.rsplit(".", 1)
            factory_fn = getattr(importlib.import_module(mod_path), attr)
            if not callable(factory_fn):
                raise ConfigFileError(f"Factory '{factory_path}' is not callable")
        register_custom_transport(
            name=name,
            transport_class=klass,
            description=description,
            config_schema=schema,
            factory_function=factory_fn,
        )
