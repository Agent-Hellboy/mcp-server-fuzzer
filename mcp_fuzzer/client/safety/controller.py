#!/usr/bin/env python3
"""Thin wrapper to manage the safety system lifecycle."""

from __future__ import annotations

from ...safety_system import start_system_blocking, stop_system_blocking


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


__all__ = ["SafetyController"]
