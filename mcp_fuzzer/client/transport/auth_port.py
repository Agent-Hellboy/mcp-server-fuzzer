#!/usr/bin/env python3
"""Authentication port for transport layer."""

from __future__ import annotations

import argparse

from ...auth import load_auth_config, setup_auth_from_env


def resolve_auth_port(args: argparse.Namespace):
    """Port for resolving authentication managers."""
    if getattr(args, "auth_config", None):
        return load_auth_config(args.auth_config)
    if getattr(args, "auth_env", False):
        return setup_auth_from_env()
    return None


__all__ = ["resolve_auth_port"]
