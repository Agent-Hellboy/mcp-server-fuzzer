#!/usr/bin/env python3
"""
Authentication Module for MCP Fuzzer

This module handles authentication for tools that require it, supporting various
auth methods like API keys, OAuth tokens, basic auth, etc.
"""

import base64
import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class AuthProvider(ABC):
    """Abstract base class for authentication providers."""

    @abstractmethod
    def get_auth_headers(self) -> Dict[str, str]:
        """Return authentication headers for requests."""
        pass

    @abstractmethod
    def get_auth_params(self) -> Dict[str, Any]:
        """Return authentication parameters for requests."""
        pass


class APIKeyAuth(AuthProvider):
    """API Key authentication provider."""

    def __init__(self, api_key: str, header_name: str = "Authorization"):
        self.api_key = api_key
        self.header_name = header_name

    def get_auth_headers(self) -> Dict[str, str]:
        return {self.header_name: f"Bearer {self.api_key}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class BasicAuth(AuthProvider):
    """Basic authentication provider."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def get_auth_headers(self) -> Dict[str, str]:
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class OAuthTokenAuth(AuthProvider):
    """OAuth token authentication provider."""

    def __init__(self, token: str, token_type: str = "Bearer"):
        self.token = token
        self.token_type = token_type

    def get_auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"{self.token_type} {self.token}"}

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class CustomHeaderAuth(AuthProvider):
    """Custom header authentication provider."""

    def __init__(self, headers: Dict[str, str]):
        self.headers = headers

    def get_auth_headers(self) -> Dict[str, str]:
        return self.headers

    def get_auth_params(self) -> Dict[str, Any]:
        return {}


class AuthManager:
    """Manages authentication for different tools and services."""

    def __init__(self):
        self.auth_providers: Dict[str, AuthProvider] = {}
        self.tool_auth_mapping: Dict[str, str] = {}

    def add_auth_provider(self, name: str, provider: AuthProvider):
        """Add an authentication provider."""
        self.auth_providers[name] = provider

    def map_tool_to_auth(self, tool_name: str, auth_provider_name: str):
        """Map a tool to use a specific authentication provider."""
        self.tool_auth_mapping[tool_name] = auth_provider_name

    def get_auth_for_tool(self, tool_name: str) -> Optional[AuthProvider]:
        """Get the authentication provider for a specific tool."""
        auth_provider_name = self.tool_auth_mapping.get(tool_name)
        if auth_provider_name:
            return self.auth_providers.get(auth_provider_name)
        return None

    def get_auth_headers_for_tool(self, tool_name: str) -> Dict[str, str]:
        """Get authentication headers for a specific tool."""
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_headers()
        return {}

    def get_auth_params_for_tool(self, tool_name: str) -> Dict[str, Any]:
        """Get authentication parameters for a specific tool."""
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_params()
        return {}


# Factory functions for easy auth setup
def create_api_key_auth(api_key: str, header_name: str = "Authorization") -> APIKeyAuth:
    """Create an API key authentication provider."""
    return APIKeyAuth(api_key, header_name)


def create_basic_auth(username: str, password: str) -> BasicAuth:
    """Create a basic authentication provider."""
    return BasicAuth(username, password)


def create_oauth_auth(token: str, token_type: str = "Bearer") -> OAuthTokenAuth:
    """Create an OAuth token authentication provider."""
    return OAuthTokenAuth(token, token_type)


def create_custom_header_auth(headers: Dict[str, str]) -> CustomHeaderAuth:
    """Create a custom header authentication provider."""
    return CustomHeaderAuth(headers)


# Environment-based auth setup
def setup_auth_from_env() -> AuthManager:
    """Set up authentication from environment variables."""
    auth_manager = AuthManager()

    # API Key auth
    api_key = os.getenv("MCP_API_KEY")
    if api_key:
        auth_manager.add_auth_provider("api_key", create_api_key_auth(api_key))

    # Basic auth
    username = os.getenv("MCP_USERNAME")
    password = os.getenv("MCP_PASSWORD")
    if username and password:
        auth_manager.add_auth_provider("basic", create_basic_auth(username, password))

    # OAuth token
    oauth_token = os.getenv("MCP_OAUTH_TOKEN")
    if oauth_token:
        auth_manager.add_auth_provider("oauth", create_oauth_auth(oauth_token))

    # Custom headers
    custom_headers = os.getenv("MCP_CUSTOM_HEADERS")
    if custom_headers:
        try:
            headers = json.loads(custom_headers)
            auth_manager.add_auth_provider("custom", create_custom_header_auth(headers))
        except json.JSONDecodeError:
            pass  # Ignore invalid JSON

    # Tool mapping
    tool_mapping = os.getenv("MCP_TOOL_AUTH_MAPPING")
    if tool_mapping:
        try:
            mapping = json.loads(tool_mapping)
            for tool_name, auth_provider_name in mapping.items():
                auth_manager.map_tool_to_auth(tool_name, auth_provider_name)
        except json.JSONDecodeError:
            pass  # Ignore invalid JSON

    return auth_manager


def load_auth_config(config_file: str) -> AuthManager:
    """Load authentication configuration from a JSON file."""
    auth_manager = AuthManager()

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Auth config file {config_file} not found")

    try:
        with open(config_file, "r") as f:
            config = json.load(f)

        # Load auth providers
        providers = config.get("providers", {})
        for name, provider_config in providers.items():
            provider_type = provider_config.get("type")

            if provider_type == "api_key":
                auth_manager.add_auth_provider(
                    name,
                    create_api_key_auth(
                        provider_config["api_key"],
                        provider_config.get("header_name", "Authorization"),
                    ),
                )
            elif provider_type == "basic":
                auth_manager.add_auth_provider(
                    name,
                    create_basic_auth(
                        provider_config["username"], provider_config["password"]
                    ),
                )
            elif provider_type == "oauth":
                auth_manager.add_auth_provider(
                    name,
                    create_oauth_auth(
                        provider_config["token"],
                        provider_config.get("token_type", "Bearer"),
                    ),
                )
            elif provider_type == "custom":
                auth_manager.add_auth_provider(
                    name, create_custom_header_auth(provider_config["headers"])
                )
            else:
                raise ValueError(f"Unknown provider type: {provider_type}")

        # Load tool mappings
        tool_mappings = config.get("tool_mapping", {})
        for tool_name, auth_provider_name in tool_mappings.items():
            auth_manager.map_tool_to_auth(tool_name, auth_provider_name)

    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Invalid JSON in auth config file: {e}", e.doc, e.pos
        )
    except Exception as e:
        raise e

    return auth_manager
