#!/usr/bin/env python3
"""Typed session configuration and CLI config container."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any


@dataclass
class CliConfig:
    """Holds parsed args plus merged configuration."""

    args: argparse.Namespace
    merged: dict[str, Any]

    def to_session_settings(self) -> SessionSettings:
        return SessionSettings(self.merged)


@dataclass
class SessionSettings:
    """Wraps the merged config dict with typed property accessors."""

    config: dict[str, Any]

    @property
    def mode(self) -> str:
        return self.config["mode"]

    @property
    def protocol(self) -> str:
        return self.config["protocol"]

    @property
    def endpoint(self) -> str:
        return self.config["endpoint"]

    @property
    def timeout(self) -> float:
        return float(self.config.get("timeout", 30.0))

    @property
    def safety_enabled(self) -> bool:
        return bool(self.config.get("safety_enabled", True))

    @property
    def output_dir(self) -> str | None:
        return self.config.get("output_dir")

    @property
    def auth_manager(self) -> Any | None:
        return self.config.get("auth_manager")

    @property
    def protocol_phase(self) -> str:
        return self.config.get("protocol_phase", "realistic")

    @property
    def spec_schema_version(self) -> Any | None:
        return self.config.get("spec_schema_version")

    @property
    def fail_if_no_tools(self) -> bool:
        return bool(self.config.get("fail_if_no_tools", False))

    @property
    def safety_report(self) -> bool:
        return bool(self.config.get("safety_report", False))

    @property
    def output_types(self) -> Any | None:
        return self.config.get("output_types")

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)

    def __getattr__(self, item: str) -> Any:
        try:
            return self.config[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


__all__ = ["CliConfig", "SessionSettings"]
