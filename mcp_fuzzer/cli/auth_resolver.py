#!/usr/bin/env python3
"""Authentication helpers for CLI."""

from __future__ import annotations

import argparse

from ..auth import load_auth_config, setup_auth_from_env


def resolve_auth_manager(args: argparse.Namespace):
    """Resolve an AuthManager based on CLI flags or environment."""
    if getattr(args, "auth_config", None):
        return load_auth_config(args.auth_config)
    if getattr(args, "auth_env", False):
        return setup_auth_from_env()
    return None


__all__ = ["resolve_auth_manager"]
