#!/usr/bin/env python3
"""Authentication port for transport layer."""

from __future__ import annotations

import argparse
import os

from ...auth import load_auth_config, setup_auth_from_env
from ...auth.yaml_loader import build_auth_from_yaml_section
from ...client.adapters import config_mediator


def _build_oauth_auth_manager(args: argparse.Namespace):
    """Build an AuthManager backed by the MCP OAuth 2.1 authorization flow."""
    from ...auth import AuthManager
    from ...auth.oauth import MCPOAuthProvider, OAuthClientConfig
    from ...exceptions import AuthConfigError

    endpoint = getattr(args, "endpoint", None)
    if not endpoint:
        raise AuthConfigError("--oauth requires --endpoint to be set")

    # CLI flags win, but fall back to the standard OAuth env vars so --oauth
    # can be used without putting client credentials on the command line.
    config = OAuthClientConfig(
        grant_type=getattr(args, "oauth_grant", "authorization_code"),
        client_id=getattr(args, "oauth_client_id", None)
        or os.getenv("MCP_OAUTH_CLIENT_ID"),
        client_secret=getattr(args, "oauth_client_secret", None)
        or os.getenv("MCP_OAUTH_CLIENT_SECRET"),
        scope=getattr(args, "oauth_scope", None) or os.getenv("MCP_OAUTH_SCOPE"),
        client_id_metadata_url=getattr(args, "oauth_client_id_metadata_url", None),
        open_browser=getattr(args, "oauth_open_browser", False),
    )
    use_cache = not getattr(args, "oauth_no_token_cache", False)
    manager = AuthManager()
    manager.add_auth_provider(
        "mcp_oauth",
        MCPOAuthProvider(endpoint, config, use_token_cache=use_cache),
    )
    manager.set_default_provider("mcp_oauth")
    return manager


def resolve_auth_port(args: argparse.Namespace):
    """Port for resolving authentication managers.

    Priority order:
    1. --oauth flag (MCP 2025-11-25 OAuth 2.1 authorization flow)
    2. --auth-config file (if provided)
    3. YAML ``auth`` section from loaded config (if present)
    4. --auth-env flag (if explicitly set)
    5. Environment variables (if any auth vars are set, auto-detect)
    6. None (no auth)
    """
    if getattr(args, "oauth", False):
        return _build_oauth_auth_manager(args)
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
