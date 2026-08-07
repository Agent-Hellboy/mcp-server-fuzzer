"""Build AuthManager instances from YAML config ``auth`` sections."""

from __future__ import annotations

from typing import Any

from ..exceptions import AuthConfigError, AuthProviderError
from .loaders import build_provider, is_known_provider_type, load_auth_from_dict
from .manager import AuthManager


def _provider_entry_to_dict(entry: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    provider_id = entry.get("id") or entry.get("name")
    if not provider_id:
        raise AuthConfigError("Each auth provider entry requires an 'id'")
    provider_type = entry.get("type")
    if not provider_type:
        raise AuthConfigError(f"Auth provider '{provider_id}' is missing 'type'")
    config = entry.get("config")
    if config is None:
        config = {k: v for k, v in entry.items() if k not in {"id", "name", "type"}}
    if not isinstance(config, dict):
        raise AuthConfigError(
            f"Auth provider '{provider_id}' config must be an object, "
            f"got {type(config).__name__}"
        )
    return str(provider_id), {"type": provider_type, **config}


def _add_provider(
    auth_manager: AuthManager, name: str, provider_config: dict[str, Any]
):
    provider_type = provider_config.get("type")
    if not is_known_provider_type(provider_type):
        raise AuthProviderError(
            f"Unknown provider type: '{provider_type}' for '{name}'"
        )
    try:
        if provider_type == "custom":
            headers = provider_config.get("headers")
            if not headers:
                raise AuthProviderError(
                    f"Provider '{name}' is type 'custom' but missing "
                    "required field 'headers'"
                )
            if not isinstance(headers, dict):
                raise AuthConfigError(
                    f"Provider '{name}' custom headers must be a dict, "
                    f"got {type(headers).__name__}"
                )
        auth_manager.add_auth_provider(
            name, build_provider(provider_type, provider_config)
        )
    except (AuthProviderError, AuthConfigError):
        raise
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthProviderError(
            f"Error configuring auth provider '{name}': {exc}"
        ) from exc


def build_auth_from_yaml_section(auth_section: dict[str, Any]) -> AuthManager:
    """Convert nested YAML ``auth`` config into an AuthManager."""
    if not isinstance(auth_section, dict):
        raise AuthConfigError(
            f"auth section must be an object, got {type(auth_section).__name__}"
        )

    providers = auth_section.get("providers")
    if isinstance(providers, dict):
        tool_mapping = auth_section.get("tool_mapping")
        if tool_mapping is None:
            tool_mapping = auth_section.get("mappings", {})
        payload = {
            "providers": providers,
            "tool_mapping": tool_mapping,
            "default_provider": auth_section.get("default_provider"),
        }
        return load_auth_from_dict(payload)

    auth_manager = AuthManager()
    if isinstance(providers, list):
        for entry in providers:
            if not isinstance(entry, dict):
                raise AuthConfigError("Each auth provider entry must be an object")
            name, provider_config = _provider_entry_to_dict(entry)
            _add_provider(auth_manager, name, provider_config)
    elif providers is not None:
        raise AuthConfigError(
            f"'providers' must be a list or dict, got {type(providers).__name__}"
        )

    tool_mapping = auth_section.get("tool_mapping")
    if tool_mapping is None:
        tool_mapping = auth_section.get("mappings", {})
    if not isinstance(tool_mapping, dict):
        raise AuthConfigError(
            f"'tool_mapping' must be a dict, got {type(tool_mapping).__name__}"
        )
    for tool_name, provider_name in tool_mapping.items():
        if provider_name not in auth_manager.auth_providers:
            raise AuthConfigError(
                f"tool_mapping references unknown provider '{provider_name}' "
                f"for tool '{tool_name}'"
            )
        auth_manager.map_tool_to_auth(str(tool_name), str(provider_name))

    default_provider = auth_section.get("default_provider")
    if default_provider:
        if default_provider not in auth_manager.auth_providers:
            raise AuthConfigError(
                f"default_provider '{default_provider}' is not configured"
            )
        auth_manager.set_default_provider(str(default_provider))

    return auth_manager
