#!/usr/bin/env python3
"""
Shared event contract definitions for runtime components.

This module exposes a lightweight protocol that both the runtime `ProcessManager`
and transport `ProcessSupervisor` use to dispatch lifecycle events. Observers can
subscribe to these events to monitor state changes without depending on
internal implementation details.

Known events:

- ``started`` (ProcessManager): emitted when a new process begins execution.
  payload keys: ``pid``, ``process_name``, ``command``.
- ``stopped`` (ProcessManager): emitted when a process stop request completes.
  payload keys: ``pid``, ``force``, ``result``.
- ``stopped_all`` (ProcessManager): emitted after ``stop_all_processes`` finishes.
  payload keys: ``force``.
- ``shutdown`` / ``shutdown_failed`` (ProcessManager): emitted during shutdown.
  payload keys: ``error`` (when failure occurs).
    - ``signal`` / ``signal_all`` (ProcessManager): emitted when signals are sent.
      payload keys: ``pid``, ``signal``, ``process_name``, ``result`` (``signal_all``
      adds ``results`` and ``failures``).
    - ``signal_failed`` (ProcessSupervisor): emitted when signal dispatch fails.
      payload keys: ``pid`` and ``error``.
- ``oversized_output`` (ProcessSupervisor): emitted whenever stdio output exceeds
  the configured cap. Payload keys: ``pid``, ``size``, ``limit``.

Future event producers should keep the payloads shallow (``dict[str, Any]``) to
avoid introducing coupling to implementation-defined objects.
"""

from __future__ import annotations

from typing import Any, Protocol

EventPayload = dict[str, Any]


class ProcessEventObserver(Protocol):
    """Protocol for callbacks that receive runtime event notifications."""

    def __call__(self, event_name: str, payload: EventPayload) -> None: ...
