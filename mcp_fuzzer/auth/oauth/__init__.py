"""MCP OAuth 2.1 authorization client (MCP 2025-11-25 authorization spec).

Implements the client-side authorization flow described in
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization:

- Protected Resource Metadata discovery (RFC 9728)
- Authorization Server Metadata discovery (RFC 8414 / OpenID Connect)
- Authorization Code grant with PKCE (S256)
- client_credentials grant for machine-to-machine fuzzing
- Dynamic Client Registration (RFC 7591) and Client ID Metadata Documents
- Resource Indicators (RFC 8707)
"""

from .canonical import canonical_resource_uri
from .pkce import PKCEChallenge, generate_pkce
from .metadata import (
    AuthorizationServerMetadata,
    ProtectedResourceMetadata,
    fetch_authorization_server_metadata,
    fetch_protected_resource_metadata,
    verify_pkce_supported,
)
from .registration import (
    build_client_id_metadata_document,
    register_dynamic_client,
)
from .authorization_code import (
    LoopbackRedirectServer,
    build_authorization_url,
    exchange_code_for_token,
    generate_state,
    refresh_access_token,
)
from .flow import (
    MCPAuthorizationFlow,
    OAuthClientConfig,
    OAuthToken,
)
from .provider import MCPOAuthProvider, create_mcp_oauth_auth

__all__ = [
    "canonical_resource_uri",
    "PKCEChallenge",
    "generate_pkce",
    "AuthorizationServerMetadata",
    "ProtectedResourceMetadata",
    "fetch_authorization_server_metadata",
    "fetch_protected_resource_metadata",
    "verify_pkce_supported",
    "build_client_id_metadata_document",
    "register_dynamic_client",
    "LoopbackRedirectServer",
    "build_authorization_url",
    "exchange_code_for_token",
    "generate_state",
    "refresh_access_token",
    "MCPAuthorizationFlow",
    "OAuthClientConfig",
    "OAuthToken",
    "MCPOAuthProvider",
    "create_mcp_oauth_auth",
]
