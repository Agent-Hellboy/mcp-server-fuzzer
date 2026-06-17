#!/usr/bin/env python3
"""Configuration facade.

A single concrete entry point for configuration access. It composes the config
submodules (``manager`` singleton + ``loader`` + ``parser`` + ``schema``) at a
layer above them, which keeps ``manager`` and ``loader`` free of an import
cycle. There is intentionally no abstract ``Port`` here — one concrete facade is
all this needs; add a seam only when a second implementation actually exists.
"""

from __future__ import annotations

from typing import Any

from .loader import ConfigLoader
from .manager import config as global_config
from .parser import load_config_file
from .schema_composer import get_config_schema


class ConfigMediator:
    """Facade that delegates configuration access to the config submodules."""

    def __init__(self, config_instance: Any = None):
        self._config = config_instance or global_config

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._config.set(key, value)

    def update(self, config_dict: dict[str, Any]) -> None:
        self._config.update(config_dict)

    def load_file(self, file_path: str) -> dict[str, Any]:
        return load_config_file(file_path)

    def apply_file(
        self,
        config_path: str | None = None,
        search_paths: list[str] | None = None,
        file_names: list[str] | None = None,
    ) -> bool:
        loader = ConfigLoader(config_instance=self._config)
        return loader.apply(
            config_path=config_path,
            search_paths=search_paths,
            file_names=file_names,
        )

    def get_schema(self) -> dict[str, Any]:
        return get_config_schema()


# Process-wide configuration facade.
config_mediator = ConfigMediator()
