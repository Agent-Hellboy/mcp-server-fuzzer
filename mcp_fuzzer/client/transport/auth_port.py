#!/usr/bin/env python3
"""Authentication port for transport layer."""

from __future__ import annotations

import argparse
import os

from ...auth import load_auth_config, setup_auth_from_env
from ...auth.yaml_loader import build_auth_from_yaml_section
from ...client.adapters import config_mediator


def resolve_auth_port(args: argparse.Namespace):
    """Port for resolving authentication managers.

    Priority order:
    1. --auth-config file (if provided)
    2. YAML ``auth`` section from loaded config (if present)
    3. --auth-env flag (if explicitly set)
    4. Environment variables (if any auth vars are set, auto-detect)
    5. None (no auth)
    """
    if getattr(args, "auth_config", None):
        return load_auth_config(args.auth_config)

    auth_section = config_mediator.get("auth")
    if isinstance(auth_section, dict) and auth_section:
        return build_auth_from_yaml_section(auth_section)

    if getattr(args, "auth_env", False):
        return setup_auth_from_env()

    auth_env_vars = [
        "MCP_API_KEY",
        "MCP_USERNAME",
        "MCP_PASSWORD",
        "MCP_OAUTH_TOKEN",
        "MCP_OAUTH_TOKEN_URL",
        "MCP_OAUTH_CLIENT_ID",
        "MCP_OAUTH_CLIENT_SECRET",
        "MCP_CUSTOM_HEADERS",
    ]
    if any(os.getenv(var) for var in auth_env_vars):
        return setup_auth_from_env()

    return None


__all__ = ["resolve_auth_port"]
