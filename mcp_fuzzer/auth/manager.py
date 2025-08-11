from typing import Any, Dict, Optional

from .providers import AuthProvider


class AuthManager:
    """Manages authentication for different tools and services."""

    def __init__(self):
        self.auth_providers: Dict[str, AuthProvider] = {}
        self.tool_auth_mapping: Dict[str, str] = {}

    def add_auth_provider(self, name: str, provider: AuthProvider):
        self.auth_providers[name] = provider

    def map_tool_to_auth(self, tool_name: str, auth_provider_name: str):
        self.tool_auth_mapping[tool_name] = auth_provider_name

    def get_auth_for_tool(self, tool_name: str) -> Optional[AuthProvider]:
        auth_provider_name = self.tool_auth_mapping.get(tool_name)
        if auth_provider_name:
            return self.auth_providers.get(auth_provider_name)
        return None

    def get_auth_headers_for_tool(self, tool_name: str) -> Dict[str, str]:
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_headers()
        return {}

    def get_auth_params_for_tool(self, tool_name: str) -> Dict[str, Any]:
        provider = self.get_auth_for_tool(tool_name)
        if provider:
            return provider.get_auth_params()
        return {}
