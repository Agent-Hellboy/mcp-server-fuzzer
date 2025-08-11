import json
import os
from typing import Dict

from .manager import AuthManager
from .providers import (
    create_api_key_auth,
    create_basic_auth,
    create_oauth_auth,
    create_custom_header_auth,
)


def setup_auth_from_env() -> AuthManager:
    auth_manager = AuthManager()

    api_key = os.getenv("MCP_API_KEY")
    if api_key:
        auth_manager.add_auth_provider("api_key", create_api_key_auth(api_key))

    username = os.getenv("MCP_USERNAME")
    password = os.getenv("MCP_PASSWORD")
    if username and password:
        auth_manager.add_auth_provider("basic", create_basic_auth(username, password))

    oauth_token = os.getenv("MCP_OAUTH_TOKEN")
    if oauth_token:
        auth_manager.add_auth_provider("oauth", create_oauth_auth(oauth_token))

    custom_headers = os.getenv("MCP_CUSTOM_HEADERS")
    if custom_headers:
        try:
            headers_json = json.loads(custom_headers)
            if isinstance(headers_json, dict):
                headers: Dict[str, str] = {
                    str(k): str(v) for k, v in headers_json.items()
                }
                auth_manager.add_auth_provider(
                    "custom", create_custom_header_auth(headers)
                )
        except (json.JSONDecodeError, TypeError):
            pass

    tool_mapping = os.getenv("MCP_TOOL_AUTH_MAPPING")
    if tool_mapping:
        try:
            mapping = json.loads(tool_mapping)
            if isinstance(mapping, dict):
                for tool_name, auth_provider_name in mapping.items():
                    auth_manager.map_tool_to_auth(
                        str(tool_name), str(auth_provider_name)
                    )
        except (json.JSONDecodeError, TypeError):
            pass

    return auth_manager


def load_auth_config(config_file: str) -> AuthManager:
    auth_manager = AuthManager()

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Auth config file {config_file} not found")

    with open(config_file, "r") as f:
        config = json.load(f)

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
            headers = provider_config.get("headers")
            if not isinstance(headers, dict):
                raise ValueError(f"Provider '{name}' custom headers must be a dict")
            headers_str: Dict[str, str] = {str(k): str(v) for k, v in headers.items()}
            auth_manager.add_auth_provider(name, create_custom_header_auth(headers_str))
        else:
            raise ValueError(f"Unknown provider type: {provider_type}")

    tool_mappings = config.get("tool_mapping", {})
    for tool_name, auth_provider_name in tool_mappings.items():
        auth_manager.map_tool_to_auth(tool_name, auth_provider_name)

    return auth_manager
