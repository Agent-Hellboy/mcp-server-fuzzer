from .providers import (
    AuthProvider,
    APIKeyAuth,
    BasicAuth,
    OAuthTokenAuth,
    CustomHeaderAuth,
    create_api_key_auth,
    create_basic_auth,
    create_oauth_auth,
    create_custom_header_auth,
)
from .manager import AuthManager
from .loaders import setup_auth_from_env, load_auth_config
from .discovery import (
    parse_www_authenticate,
    extract_resource_metadata_url,
    extract_requested_scopes,
    build_protected_resource_metadata_urls,
    build_authorization_server_metadata_urls,
)

__all__ = [
    "AuthProvider",
    "APIKeyAuth",
    "BasicAuth",
    "OAuthTokenAuth",
    "CustomHeaderAuth",
    "create_api_key_auth",
    "create_basic_auth",
    "create_oauth_auth",
    "create_custom_header_auth",
    "AuthManager",
    "setup_auth_from_env",
    "load_auth_config",
    "parse_www_authenticate",
    "extract_resource_metadata_url",
    "extract_requested_scopes",
    "build_protected_resource_metadata_urls",
    "build_authorization_server_metadata_urls",
]
