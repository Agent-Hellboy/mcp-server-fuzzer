from typing import Any

from .providers import AuthProvider


class AuthManager:
    """Manages authentication for different tools and services."""

    def __init__(self):
        self.auth_providers: dict[str, AuthProvider] = {}
        self.tool_auth_mapping: dict[str, str] = {}
        self.default_provider: str | None = None

    def add_auth_provider(self, name: str, provider: AuthProvider):
        self.auth_providers[name] = provider

    def map_tool_to_auth(self, tool_name: str, auth_provider_name: str):
        self.tool_auth_mapping[tool_name] = auth_provider_name

    def set_default_provider(self, provider_name: str):
        """Set the default auth provider for transport-level authentication.

        Args:
            provider_name: Name of the auth provider to use as default
        """
        self.default_provider = provider_name

    def get_auth_for_tool(self, tool_name: str) -> AuthProvider | None:
        auth_provider_name = self.tool_auth_mapping.get(tool_name)
        if auth_provider_name:
            return self.auth_providers.get(auth_provider_name)
        return None

    def get_auth_headers_for_tool(self, tool_name: str) -> dict[str, str]:
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_headers()
        return {}

    def get_auth_params_for_tool(self, tool_name: str) -> dict[str, Any]:
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_params()
        return {}

    def get_default_auth_headers(self) -> dict[str, str]:
        """Get auth headers from default provider for transport authentication.

        Returns:
            Dict of auth headers, or empty dict if no default provider is set
        """
        if self.default_provider and self.default_provider in self.auth_providers:
            return self.auth_providers[self.default_provider].get_auth_headers()
        return {}
