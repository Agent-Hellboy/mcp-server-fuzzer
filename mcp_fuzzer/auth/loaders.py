import json
import logging
import os

from ..exceptions import AuthConfigError, AuthProviderError
from .manager import AuthManager
from .providers import (
    create_api_key_auth,
    create_basic_auth,
    create_oauth_auth,
    create_custom_header_auth,
)

logger = logging.getLogger(__name__)


def setup_auth_from_env() -> AuthManager:
    auth_manager = AuthManager()

    api_key = os.getenv("MCP_API_KEY")
    header_name = os.getenv("MCP_HEADER_NAME")
    prefix = os.getenv("MCP_PREFIX")
    if api_key:
        auth_manager.add_auth_provider(
            "api_key",
            create_api_key_auth(
                api_key,
                header_name if header_name is not None else "Authorization",
                prefix if prefix is not None else "Bearer",
            ),
        )

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
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Failed to parse MCP_CUSTOM_HEADERS as JSON: %s", exc)

    tool_mapping = os.getenv("MCP_TOOL_AUTH_MAPPING")
    if tool_mapping:
        try:
            mapping = json.loads(tool_mapping)
            if isinstance(mapping, dict):
                for tool_name, auth_provider_name in mapping.items():
                    auth_manager.map_tool_to_auth(
                        str(tool_name), str(auth_provider_name)
                    )
        except (json.JSONDecodeError, TypeError) as exc:
            logger.debug("Failed to parse MCP_TOOL_AUTH_MAPPING as JSON: %s", exc)

    default_provider = os.getenv("MCP_DEFAULT_AUTH_PROVIDER")
    if default_provider:
        auth_manager.set_default_provider(default_provider)

    return auth_manager


def load_auth_config(config_file: str) -> AuthManager:
    auth_manager = AuthManager()

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Auth config file {config_file} not found")

    with open(config_file, "r") as f:
        config = json.load(f)

    providers = config.get("providers", {})
    for name, provider_config in providers.items():
        if not isinstance(provider_config, dict):
            raise AuthProviderError(
                f"Error configuring auth provider '{name}': "
                f"expected an object, got {type(provider_config).__name__}"
            )
        provider_type = provider_config.get("type")

        try:
            if provider_type == "api_key":
                if "api_key" not in provider_config:
                    raise AuthProviderError(
                        f"Provider '{name}' is type 'api_key' but missing "
                        "required field 'api_key'. Expected: "
                        "{'type': 'api_key', 'api_key': 'YOUR_API_KEY'}"
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
                    raise AuthProviderError(
                        f"Provider '{name}' is type 'basic' but missing "
                        "required field 'username'. Expected: "
                        "{'type': 'basic', 'username': 'user', 'password': 'pass'}"
                    )
                if "password" not in provider_config:
                    raise AuthProviderError(
                        f"Provider '{name}' is type 'basic' but missing "
                        "required field 'password'. Expected: "
                        "{'type': 'basic', 'username': 'user', 'password': 'pass'}"
                    )
                auth_manager.add_auth_provider(
                    name,
                    create_basic_auth(
                        provider_config["username"], provider_config["password"]
                    ),
                )
            elif provider_type == "oauth":
                if "token" not in provider_config:
                    raise AuthProviderError(
                        f"Provider '{name}' is type 'oauth' but missing "
                        "required field 'token'. Expected: "
                        "{'type': 'oauth', 'token': 'YOUR_TOKEN'}"
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
                    raise AuthProviderError(
                        f"Provider '{name}' is type 'custom' but missing "
                        "required field 'headers'. Expected: "
                        "{'type': 'custom', 'headers': {'X-Header': 'value'}}"
                    )
                if not isinstance(headers, dict):
                    raise AuthProviderError(
                        f"Provider '{name}' custom headers must be a dict, "
                        f"got {type(headers).__name__}"
                    )
                headers_str: dict[str, str] = {
                    str(k): str(v) for k, v in headers.items()
                }
                auth_manager.add_auth_provider(
                    name, create_custom_header_auth(headers_str)
                )
            else:
                raise AuthProviderError(
                    f"Unknown provider type: '{provider_type}' for provider '{name}'. "
                    f"Supported types: api_key, basic, oauth, custom"
                )
        except AuthProviderError:
            raise
        except (KeyError, ValueError, TypeError) as e:
            raise AuthProviderError(
                f"Error configuring auth provider '{name}': {str(e)}"
            ) from e

    tool_mappings = config.get("tool_mapping")
    legacy_tool_mappings = config.get("tool_mappings")
    if tool_mappings and legacy_tool_mappings:
        raise AuthConfigError(
            "Both 'tool_mapping' and legacy 'tool_mappings' are defined. "
            "Please use only 'tool_mapping'."
        )

    final_tool_mappings = tool_mappings or legacy_tool_mappings or {}
    if final_tool_mappings and not isinstance(final_tool_mappings, dict):
        raise AuthConfigError(
            f"'tool_mapping' must be a dict, got {type(final_tool_mappings).__name__}"
        )

    for tool_name, auth_provider_name in final_tool_mappings.items():
        auth_manager.map_tool_to_auth(tool_name, auth_provider_name)

    default_provider = config.get("default_provider")
    if default_provider:
        auth_manager.set_default_provider(default_provider)

    return auth_manager
