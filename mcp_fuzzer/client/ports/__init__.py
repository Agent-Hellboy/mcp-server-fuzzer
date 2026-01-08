#!/usr/bin/env python3
"""Port interfaces for Port and Adapter pattern.

Ports define the contracts (interfaces) that adapters must implement.
All modules should depend on ports, not concrete implementations.
"""

from .config_port import ConfigPort

__all__ = ["ConfigPort"]
