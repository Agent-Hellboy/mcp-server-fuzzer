#!/usr/bin/env python3
"""Authentication port for transport layer."""

from __future__ import annotations

import argparse
import os

from ...auth import load_auth_config, setup_auth_from_env


def resolve_auth_port(args: argparse.Namespace):
    """Port for resolving authentication managers.
    
    Priority order:
    1. --auth-config file (if provided)
    2. --auth-env flag (if explicitly set)
    3. Environment variables (if any auth vars are set, auto-detect)
    4. None (no auth)
    """
    if getattr(args, "auth_config", None):
        return load_auth_config(args.auth_config)
    if getattr(args, "auth_env", False):
        return setup_auth_from_env()
    
    # Auto-detect: check if any auth environment variables are set
    auth_env_vars = [
        "MCP_API_KEY",
        "MCP_USERNAME",
        "MCP_PASSWORD",
        "MCP_OAUTH_TOKEN",
        "MCP_CUSTOM_HEADERS",
    ]
    if any(os.getenv(var) for var in auth_env_vars):
        return setup_auth_from_env()
    
    return None


__all__ = ["resolve_auth_port"]
