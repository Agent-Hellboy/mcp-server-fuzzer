#!/usr/bin/env python3
"""Adapter implementations for Port and Adapter pattern.

Adapters implement the ports (interfaces) by adapting external modules.
This is where the mediation between modules happens.
"""

from .config_adapter import ConfigAdapter, config_mediator

__all__ = ["ConfigAdapter", "config_mediator"]
