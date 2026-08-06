import json
import logging
import os
from collections.abc import Callable
from typing import Any

from ..exceptions import AuthConfigError, AuthProviderError
from .manager import AuthManager
from .providers import (
    AuthProvider,
    create_api_key_auth,
    create_basic_auth,
    create_oauth_auth,
    create_oauth_client_credentials_auth,
    create_custom_header_auth,
)

logger = logging.getLogger(__name__)

# Required config keys per scheme plus the example echoed in the error message.
_PROVIDER_SPECS: dict[str, tuple[tuple[str, ...], str]] = {
    "api_key": (
        ("api_key",),
        "{'type': 'api_key', 'api_key': 'YOUR_API_KEY'}",
    ),
    "basic": (
        ("username", "password"),
        "{'type': 'basic', 'username': 'user', 'password': 'pass'}",
    ),
    "oauth": (
        ("token",),
        "{'type': 'oauth', 'token': 'YOUR_TOKEN'}",
    ),
    "oauth_client_credentials": (
        ("token_url", "client_id", "client_secret"),
        "{'type': 'oauth_client_credentials', "
        "'token_url': 'https://auth.example.com/token', "
        "'client_id': 'CLIENT_ID', "
        "'client_secret': 'CLIENT_SECRET'}",
    ),
    "custom": (
        ("headers",),
        "{'type': 'custom', 'headers': {'X-Header': 'value'}}",
    ),
}

# Construction only -- callers validate first. Shared with the YAML loader so
# the per-scheme defaults live in exactly one place.
_PROVIDER_BUILDERS: dict[str, Callable[[dict[str, Any]], AuthProvider]] = {
    "api_key": lambda cfg: create_api_key_auth(
        cfg["api_key"],
        cfg.get("header_name", "Authorization"),
        cfg.get("prefix", "Bearer"),
    ),
    "basic": lambda cfg: create_basic_auth(cfg["username"], cfg["password"]),
    "oauth": lambda cfg: create_oauth_auth(
        cfg["token"],
        cfg.get("token_type", "Bearer"),
    ),
    "oauth_client_credentials": lambda cfg: create_oauth_client_credentials_auth(
        cfg["token_url"],
        cfg["client_id"],
        cfg["client_secret"],
        cfg.get("scope"),
        cfg.get("token_type", "Bearer"),
        float(cfg.get("timeout", 10.0)),
    ),
    "custom": lambda cfg: create_custom_header_auth(
        {str(k): str(v) for k, v in cfg["headers"].items()}
    ),
}


def build_provider(
    provider_type: str, provider_config: dict[str, Any]
) -> AuthProvider:
    """Build an auth provider from an already-validated config mapping."""
    return _PROVIDER_BUILDERS[provider_type](provider_config)


def is_known_provider_type(provider_type: Any) -> bool:
    """Return True when ``provider_type`` names a supported auth scheme."""
    return isinstance(provider_type, str) and provider_type in _PROVIDER_BUILDERS


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

    oauth_client_id = os.getenv("MCP_OAUTH_CLIENT_ID")
    oauth_client_secret = os.getenv("MCP_OAUTH_CLIENT_SECRET")
    oauth_token_url = os.getenv("MCP_OAUTH_TOKEN_URL")
    if oauth_client_id and oauth_client_secret and oauth_token_url:
        auth_manager.add_auth_provider(
            "oauth_client_credentials",
            create_oauth_client_credentials_auth(
                oauth_token_url,
                oauth_client_id,
                oauth_client_secret,
                os.getenv("MCP_OAUTH_SCOPE"),
            ),
        )

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
    elif len(auth_manager.auth_providers) == 1:
        # If only one provider exists, set it as default for convenience
        provider_name = next(iter(auth_manager.auth_providers.keys()))
        auth_manager.set_default_provider(provider_name)
    elif "api_key" in auth_manager.auth_providers:
        # Prefer api_key as default if multiple providers exist
        auth_manager.set_default_provider("api_key")

    return auth_manager


def load_auth_config(config_file: str) -> AuthManager:
    auth_manager = AuthManager()

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Auth config file {config_file} not found")

    with open(config_file, "r") as f:
        config = json.load(f)

    populate_auth_manager(auth_manager, config)
    return auth_manager


def load_auth_from_dict(config: dict[str, Any]) -> AuthManager:
    """Load auth configuration from an in-memory dict."""
    auth_manager = AuthManager()
    populate_auth_manager(auth_manager, config)
    return auth_manager


def _missing_field_error(
    name: str, provider_type: str, field: str
) -> AuthProviderError:
    _, example = _PROVIDER_SPECS[provider_type]
    return AuthProviderError(
        f"Provider '{name}' is type '{provider_type}' but missing "
        f"required field '{field}'. Expected: {example}"
    )


def _add_configured_provider(
    auth_manager: AuthManager, name: str, provider_config: dict[str, Any]
) -> None:
    provider_type = provider_config.get("type")
    if not is_known_provider_type(provider_type):
        raise AuthProviderError(
            f"Unknown provider type: '{provider_type}' for provider '{name}'. "
            "Supported types: api_key, basic, oauth, "
            "oauth_client_credentials, custom"
        )

    required_fields, _ = _PROVIDER_SPECS[provider_type]
    try:
        for field in required_fields:
            if field not in provider_config:
                raise _missing_field_error(name, provider_type, field)
        if provider_type == "custom":
            headers = provider_config["headers"]
            if not headers:
                raise _missing_field_error(name, "custom", "headers")
            if not isinstance(headers, dict):
                raise AuthProviderError(
                    f"Provider '{name}' custom headers must be a dict, "
                    f"got {type(headers).__name__}"
                )
        auth_manager.add_auth_provider(
            name, build_provider(provider_type, provider_config)
        )
    except AuthProviderError:
        raise
    except (KeyError, ValueError, TypeError) as e:
        raise AuthProviderError(
            f"Error configuring auth provider '{name}': {str(e)}"
        ) from e


def populate_auth_manager(auth_manager: AuthManager, config: dict[str, Any]) -> None:
    if not isinstance(config, dict):
        raise AuthConfigError(
            f"Auth config must be a JSON object, got {type(config).__name__}"
        )

    providers = config.get("providers", {})
    if not isinstance(providers, dict):
        raise AuthConfigError(
            f"'providers' must be an object, got {type(providers).__name__}"
        )
    for name, provider_config in providers.items():
        if not isinstance(provider_config, dict):
            raise AuthProviderError(
                f"Error configuring auth provider '{name}': "
                f"expected an object, got {type(provider_config).__name__}"
            )
        _add_configured_provider(auth_manager, name, provider_config)

    if "tool_mappings" in config:
        raise AuthConfigError(
            "'tool_mappings' is no longer supported. Use 'tool_mapping'."
        )

    final_tool_mappings = config.get("tool_mapping")
    if final_tool_mappings is None:
        final_tool_mappings = config.get("mappings", {})
    if not isinstance(final_tool_mappings, dict):
        raise AuthConfigError(
            f"'tool_mapping' must be a dict, got {type(final_tool_mappings).__name__}"
        )

    for tool_name, auth_provider_name in final_tool_mappings.items():
        if not isinstance(auth_provider_name, str):
            raise AuthConfigError(
                f"tool_mapping value for tool '{tool_name}' must be a string, "
                f"got {type(auth_provider_name).__name__}"
            )
        if auth_provider_name not in auth_manager.auth_providers:
            raise AuthConfigError(
                f"tool_mapping references unknown provider '{auth_provider_name}' "
                f"for tool '{tool_name}'. Known providers: "
                f"{', '.join(sorted(auth_manager.auth_providers)) or '(none)'}"
            )
        auth_manager.map_tool_to_auth(str(tool_name), auth_provider_name)

    default_provider = config.get("default_provider")
    if default_provider:
        if default_provider not in auth_manager.auth_providers:
            raise AuthConfigError(
                f"default_provider '{default_provider}' is not configured. "
                f"Known providers: "
                f"{', '.join(sorted(auth_manager.auth_providers)) or '(none)'}"
            )
        auth_manager.set_default_provider(default_provider)
