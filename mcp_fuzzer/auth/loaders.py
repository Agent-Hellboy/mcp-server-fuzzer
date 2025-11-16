import json
import os

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
                headers: dict[str, str] = {
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
        
        try:
            if provider_type == "api_key":
                if "api_key" not in provider_config:
                    raise ValueError(
                        f"Provider '{name}' is type 'api_key' but missing required field 'api_key'. "
                        f"Expected: {{'type': 'api_key', 'api_key': 'YOUR_API_KEY'}}"
                    )
                auth_manager.add_auth_provider(
                    name,
                    create_api_key_auth(
                        provider_config["api_key"],
                        provider_config.get("header_name", "Authorization"),
                        provider_config.get("prefix", "Bearer"),
                    ),
                )
            elif provider_type == "basic":
                if "username" not in provider_config:
                    raise ValueError(
                        f"Provider '{name}' is type 'basic' but missing required field 'username'. "
                        f"Expected: {{'type': 'basic', 'username': 'user', 'password': 'pass'}}"
                    )
                if "password" not in provider_config:
                    raise ValueError(
                        f"Provider '{name}' is type 'basic' but missing required field 'password'. "
                        f"Expected: {{'type': 'basic', 'username': 'user', 'password': 'pass'}}"
                    )
                auth_manager.add_auth_provider(
                    name,
                    create_basic_auth(
                        provider_config["username"], provider_config["password"]
                    ),
                )
            elif provider_type == "oauth":
                if "token" not in provider_config:
                    raise ValueError(
                        f"Provider '{name}' is type 'oauth' but missing required field 'token'. "
                        f"Expected: {{'type': 'oauth', 'token': 'YOUR_TOKEN'}}"
                    )
                auth_manager.add_auth_provider(
                    name,
                    create_oauth_auth(
                        provider_config["token"],
                        provider_config.get("token_type", "Bearer"),
                    ),
                )
            elif provider_type == "custom":
                headers = provider_config.get("headers")
                if not headers:
                    raise ValueError(
                        f"Provider '{name}' is type 'custom' but missing required field 'headers'. "
                        f"Expected: {{'type': 'custom', 'headers': {{'X-Header': 'value'}}}}"
                    )
                if not isinstance(headers, dict):
                    raise ValueError(f"Provider '{name}' custom headers must be a dict, got {type(headers).__name__}")
                headers_str: dict[str, str] = {str(k): str(v) for k, v in headers.items()}
                auth_manager.add_auth_provider(name, create_custom_header_auth(headers_str))
            else:
                raise ValueError(
                    f"Unknown provider type: '{provider_type}' for provider '{name}'. "
                    f"Supported types: api_key, basic, oauth, custom"
                )
        except (KeyError, ValueError) as e:
            raise ValueError(f"Error configuring auth provider '{name}': {str(e)}")

    tool_mappings = config.get("tool_mapping", {})
    for tool_name, auth_provider_name in tool_mappings.items():
        auth_manager.map_tool_to_auth(tool_name, auth_provider_name)

    return auth_manager
