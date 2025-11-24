#!/usr/bin/env python3
"""Settings containers for the client pipeline."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any


@dataclass
class CliConfig:
    """Holds parsed args plus merged configuration."""

    args: argparse.Namespace
    merged: dict[str, Any]

    def to_client_settings(self) -> "ClientSettings":
        return ClientSettings(self.merged)


@dataclass
class ClientSettings:
    """Lightweight wrapper around the merged configuration."""

    data: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def __getattr__(self, item: str) -> Any:
        try:
            return self.data[item]
        except KeyError as exc:
            raise AttributeError(item) from exc


__all__ = ["CliConfig", "ClientSettings"]
