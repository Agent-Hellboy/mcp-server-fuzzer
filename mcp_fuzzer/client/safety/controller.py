#!/usr/bin/env python3
"""Thin wrapper to manage the safety system lifecycle."""

from __future__ import annotations
from typing import Protocol
from ...safety_system import start_system_blocking, stop_system_blocking


class SafetyPort(Protocol):
    """Port interface for safety operations."""

    def configure_network_policy(
        self,
        deny_network_by_default: bool | None = None,
        extra_allowed_hosts: list[str] | None = None,
        reset_allowed_hosts: bool = False,
    ) -> None: ...

    def start_if_enabled(self, enabled: bool) -> None: ...
    def stop_if_started(self) -> None: ...


class SafetyController:
    def __init__(self):
        self._started = False

    def start_if_enabled(self, enabled: bool) -> None:
        if enabled:
            start_system_blocking()
            self._started = True

    def stop_if_started(self) -> None:
        if self._started:
            try:
                stop_system_blocking()
            finally:
                self._started = False

    def configure_network_policy(
        self,
        deny_network_by_default: bool | None = None,
        extra_allowed_hosts: list[str] | None = None,
        reset_allowed_hosts: bool = False,
    ) -> None:
        """Port for configuring network safety policies."""
        from ...safety_system.policy import configure_network_policy

        configure_network_policy(
            deny_network_by_default=deny_network_by_default,
            extra_allowed_hosts=extra_allowed_hosts,
            reset_allowed_hosts=reset_allowed_hosts,
        )


__all__ = ["SafetyController"]
