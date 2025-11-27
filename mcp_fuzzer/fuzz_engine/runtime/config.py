#!/usr/bin/env python3
"""
Process configuration helpers for MCP Fuzzer runtime.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass
class ProcessConfig:
    """Configuration for a managed process."""

    command: list[str]
    cwd: str | Path | None = None
    env: dict[str, str] | None = None
    timeout: float = 30.0
    auto_kill: bool = True
    name: str = "unknown"
    activity_callback: Callable[[], float] | None = None

    @classmethod
    def from_config(cls, config: dict[str, Any], **overrides) -> "ProcessConfig":
        """Create a ProcessConfig using the provided config.

        Only ``process_timeout`` and ``auto_kill`` are read from ``config``;
        every other argument (especially the required ``command``) must be
        supplied via ``overrides`` to avoid ``TypeError``.
        """
        return cls(
            timeout=config.get("process_timeout", 30.0),
            auto_kill=config.get("auto_kill", True),
            **overrides,
        )


@dataclass
class WatchdogConfig:
    """Configuration for the process watchdog."""

    check_interval: float = 1.0  # How often to check processes (seconds)
    process_timeout: float = 30.0  # Time before process is considered hanging (seconds)
    extra_buffer: float = 5.0  # Extra time before auto-kill (seconds)
    max_hang_time: float = 60.0  # Maximum time before force kill (seconds)
    auto_kill: bool = True  # Whether to automatically kill hanging processes

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "WatchdogConfig":
        """Create WatchdogConfig from configuration dictionary."""
        return cls(
            check_interval=config.get("watchdog_check_interval", 1.0),
            process_timeout=config.get("watchdog_process_timeout", 30.0),
            extra_buffer=config.get("watchdog_extra_buffer", 5.0),
            max_hang_time=config.get("watchdog_max_hang_time", 60.0),
            auto_kill=config.get("auto_kill", True),
        )


class ProcessConfigBuilder:
    """Builder to compose ProcessConfig instances with clear, chainable options."""

    def __init__(self) -> None:
        self._command: list[str] = []
        self._cwd: str | Path | None = None
        self._env: dict[str, str] | None = None
        self._timeout: float = 30.0
        self._auto_kill: bool = True
        self._name: str = "unknown"
        self._activity_callback: Callable[[], float] | None = None

    def with_command(self, command: list[str]) -> "ProcessConfigBuilder":
        self._command = command
        return self

    def with_cwd(self, cwd: str | Path | None) -> "ProcessConfigBuilder":
        self._cwd = cwd
        return self

    def with_env(self, env: dict[str, str] | None) -> "ProcessConfigBuilder":
        self._env = env
        return self

    def with_timeout(self, timeout: float) -> "ProcessConfigBuilder":
        self._timeout = timeout
        return self

    def with_auto_kill(self, auto_kill: bool) -> "ProcessConfigBuilder":
        self._auto_kill = auto_kill
        return self

    def with_name(self, name: str) -> "ProcessConfigBuilder":
        self._name = name
        return self

    def with_activity_callback(
        self, callback: Callable[[], float] | None
    ) -> "ProcessConfigBuilder":
        self._activity_callback = callback
        return self

    def build(self) -> ProcessConfig:
        if not self._command:
            raise ValueError(
                "ProcessConfigBuilder.build() requires a non-empty command"
            )
        return ProcessConfig(
            command=self._command,
            cwd=self._cwd,
            env=self._env,
            timeout=self._timeout,
            auto_kill=self._auto_kill,
            name=self._name,
            activity_callback=self._activity_callback,
        )


def merge_env(
    base: dict[str, str] | None, overrides: dict[str, str] | None
) -> dict[str, str]:
    """Merge environment dictionaries, defaulting to OS env.

    When both ``base`` and ``overrides`` are ``None``, the host ``os.environ``
    is copied wholesale into the result, so callers should sanitize the payload
    if they wish to avoid leaking system variables into subprocesses.
    """
    merged = base.copy() if base is not None else os.environ.copy()
    if overrides:
        merged.update(overrides)
    return merged
