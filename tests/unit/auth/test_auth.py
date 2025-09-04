#!/usr/bin/env python3
"""
Unit tests for Auth module
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, call, patch

import pytest
from mcp_fuzzer.auth import (
    APIKeyAuth,
    AuthManager,
    AuthProvider,
    BasicAuth,
    CustomHeaderAuth,
    OAuthTokenAuth,
    create_api_key_auth,
    create_basic_auth,
    create_custom_header_auth,
    create_oauth_auth,
    load_auth_config,
    setup_auth_from_env,
)

pytestmark = [pytest.mark.unit, pytest.mark.auth]


def test_auth_provider_abstract():
    """Test that AuthProvider is properly abstract."""
    # Should not be able to instantiate AuthProvider directly
    with pytest.raises(TypeError):
        AuthProvider()


# Test cases for APIKeyAuth class
@pytest.fixture
def api_key_auth():
    """Fixture for APIKeyAuth test cases."""
    return APIKeyAuth("test_api_key", "X-API-Key")


def test_api_key_auth_init(api_key_auth):
    """Test APIKeyAuth initialization."""
    assert api_key_auth.api_key == "test_api_key"
    assert api_key_auth.header_name == "X-API-Key"


def test_api_key_auth_init_default_header():
    """Test APIKeyAuth initialization with default header."""
    auth = APIKeyAuth("test_api_key")
    assert auth.header_name == "Authorization"


def test_api_key_auth_get_auth_headers(api_key_auth):
    """Test getting auth headers."""
    headers = api_key_auth.get_auth_headers()
    assert "X-API-Key" in headers
    assert headers["X-API-Key"] == "Bearer test_api_key"


def test_api_key_auth_get_auth_headers_default_header():
    """Test getting auth headers with default header."""
    auth = APIKeyAuth("test_api_key")
    headers = auth.get_auth_headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer test_api_key"


def test_api_key_auth_get_auth_params(api_key_auth):
    """Test getting auth params."""
    params = api_key_auth.get_auth_params()
    assert params == {}


# Test cases for BasicAuth class
@pytest.fixture
def basic_auth():
    """Fixture for BasicAuth test cases."""
    return BasicAuth("test_user", "test_password")


def test_basic_auth_init(basic_auth):
    """Test BasicAuth initialization."""
    assert basic_auth.username == "test_user"
    assert basic_auth.password == "test_password"


def test_basic_auth_get_auth_headers(basic_auth):
    """Test getting auth headers."""
    headers = basic_auth.get_auth_headers()
    assert "Authorization" in headers
    # Check that the credentials are base64 encoded
    assert headers["Authorization"].startswith("Basic ")

    # Decode and verify the credentials
    import base64

    encoded_credentials = headers["Authorization"].replace("Basic ", "")
    decoded_credentials = base64.b64decode(encoded_credentials).decode()
    assert decoded_credentials == "test_user:test_password"


def test_basic_auth_get_auth_params(basic_auth):
    """Test getting auth params."""
    params = basic_auth.get_auth_params()
    assert params == {}


# Test cases for OAuthTokenAuth class
@pytest.fixture
def oauth_token_auth():
    """Fixture for OAuthTokenAuth test cases."""
    return OAuthTokenAuth("test_token", "Bearer")


def test_oauth_token_auth_init(oauth_token_auth):
    """Test OAuthTokenAuth initialization."""
    assert oauth_token_auth.token == "test_token"
    assert oauth_token_auth.token_type == "Bearer"


def test_oauth_token_auth_init_default_token_type():
    """Test OAuthTokenAuth initialization with default token type."""
    auth = OAuthTokenAuth("test_token")
    assert auth.token_type == "Bearer"


def test_oauth_token_auth_get_auth_headers(oauth_token_auth):
    """Test getting auth headers."""
    headers = oauth_token_auth.get_auth_headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer test_token"


def test_oauth_token_auth_get_auth_headers_custom_token_type():
    """Test getting auth headers with custom token type."""
    auth = OAuthTokenAuth("test_token", "Token")
    headers = auth.get_auth_headers()
    assert "Authorization" in headers
    assert headers["Authorization"] == "Token test_token"


def test_oauth_token_auth_get_auth_params(oauth_token_auth):
    """Test getting auth params."""
    params = oauth_token_auth.get_auth_params()
    assert params == {}


# Test cases for CustomHeaderAuth class
@pytest.fixture
def custom_headers():
    """Fixture for header dictionary."""
    return {
        "X-Custom-Header": "custom_value",
        "X-API-Key": "api_key_value",
    }


@pytest.fixture
def custom_header_auth(custom_headers):
    """Fixture for CustomHeaderAuth test cases."""
    return CustomHeaderAuth(custom_headers)


def test_custom_header_auth_init(custom_header_auth, custom_headers):
    """Test CustomHeaderAuth initialization."""
    assert custom_header_auth.headers == custom_headers


def test_custom_header_auth_get_auth_headers(custom_header_auth, custom_headers):
    """Test getting auth headers."""
    headers = custom_header_auth.get_auth_headers()
    assert headers == custom_headers
    assert "X-Custom-Header" in headers
    assert "X-API-Key" in headers
    assert headers["X-Custom-Header"] == "custom_value"
    assert headers["X-API-Key"] == "api_key_value"


def test_custom_header_auth_get_auth_params(custom_header_auth):
    """Test getting auth params."""
    params = custom_header_auth.get_auth_params()
    assert params == {}


# Test cases for AuthManager class
@pytest.fixture
def auth_manager():
    """Fixture for AuthManager test cases."""
    return AuthManager()


def test_auth_manager_init(auth_manager):
    """Test AuthManager initialization."""
    assert auth_manager.auth_providers == {}
    assert auth_manager.tool_auth_mapping == {}


def test_auth_manager_add_auth_provider(auth_manager):
    """Test adding auth provider."""
    auth_provider = APIKeyAuth("test_key")
    auth_manager.add_auth_provider("test_provider", auth_provider)
    assert "test_provider" in auth_manager.auth_providers
    assert auth_manager.auth_providers["test_provider"] == auth_provider


def test_auth_manager_map_tool_to_auth(auth_manager):
    """Test mapping tool to auth provider."""
    auth_manager.map_tool_to_auth("test_tool", "test_provider")
    assert "test_tool" in auth_manager.tool_auth_mapping
    assert auth_manager.tool_auth_mapping["test_tool"] == "test_provider"


def test_auth_manager_get_auth_for_tool_mapped(auth_manager):
    """Test getting auth for mapped tool."""
    auth_provider = APIKeyAuth("test_key")
    auth_manager.add_auth_provider("test_provider", auth_provider)
    auth_manager.map_tool_to_auth("test_tool", "test_provider")
    result = auth_manager.get_auth_for_tool("test_tool")
    assert result == auth_provider


def test_auth_manager_get_auth_for_tool_not_mapped(auth_manager):
    """Test getting auth for unmapped tool."""
    result = auth_manager.get_auth_for_tool("test_tool")
    assert result is None


def test_auth_manager_get_auth_headers_for_tool_mapped(auth_manager):
    """Test getting auth headers for mapped tool."""
    auth_provider = APIKeyAuth("test_key", "X-API-Key")
    auth_manager.add_auth_provider("test_provider", auth_provider)
    auth_manager.map_tool_to_auth("test_tool", "test_provider")
    headers = auth_manager.get_auth_headers_for_tool("test_tool")
    assert "X-API-Key" in headers
    assert headers["X-API-Key"] == "Bearer test_key"


def test_auth_manager_get_auth_headers_for_tool_not_mapped(auth_manager):
    """Test getting auth headers for unmapped tool."""
    headers = auth_manager.get_auth_headers_for_tool("test_tool")
    assert headers == {}


def test_auth_manager_get_auth_params_for_tool_mapped(auth_manager):
    """Test getting auth params for mapped tool."""
    auth_provider = APIKeyAuth("test_key")
    auth_manager.add_auth_provider("test_provider", auth_provider)
    auth_manager.map_tool_to_auth("test_tool", "test_provider")
    params = auth_manager.get_auth_params_for_tool("test_tool")
    assert params == {}


def test_auth_manager_get_auth_params_for_tool_not_mapped(auth_manager):
    """Test getting auth params for unmapped tool."""
    params = auth_manager.get_auth_params_for_tool("test_tool")
    assert params == {}


# Test cases for auth factory functions
def test_create_api_key_auth():
    """Test creating API key auth."""
    auth = create_api_key_auth("test_key", "X-API-Key")
    assert isinstance(auth, APIKeyAuth)
    assert auth.api_key == "test_key"
    assert auth.header_name == "X-API-Key"


def test_create_basic_auth():
    """Test creating basic auth."""
    auth = create_basic_auth("test_user", "test_password")
    assert isinstance(auth, BasicAuth)
    assert auth.username == "test_user"
    assert auth.password == "test_password"


def test_create_oauth_auth():
    """Test creating OAuth auth."""
    auth = create_oauth_auth("test_token", "Bearer")
    assert isinstance(auth, OAuthTokenAuth)
    assert auth.token == "test_token"
    assert auth.token_type == "Bearer"


def test_create_custom_header_auth():
    """Test creating custom header auth."""
    headers = {"X-Custom-Header": "custom_value"}
    auth = create_custom_header_auth(headers)
    assert isinstance(auth, CustomHeaderAuth)
    assert auth.headers == headers


# Test cases for setup_auth_from_env function
def test_setup_auth_from_env_all_providers():
    """Test setting up auth from environment with all providers."""
    env_vars = {
        "MCP_API_KEY": "test_api_key",
        "MCP_USERNAME": "test_user",
        "MCP_PASSWORD": "test_password",
        "MCP_OAUTH_TOKEN": "test_token",
        "MCP_CUSTOM_HEADERS": '{"X-Custom": "value"}',
    }
    with patch.dict(os.environ, env_vars):
        auth_manager = setup_auth_from_env()

        assert isinstance(auth_manager, AuthManager)
        assert "api_key" in auth_manager.auth_providers
        assert "basic" in auth_manager.auth_providers
        assert "oauth" in auth_manager.auth_providers
        assert "custom" in auth_manager.auth_providers


def test_setup_auth_from_env_no_vars():
    """Test setting up auth from environment with no variables."""
    with patch.dict(os.environ, {}, clear=True):
        auth_manager = setup_auth_from_env()

        assert isinstance(auth_manager, AuthManager)
        assert auth_manager.auth_providers == {}


def test_setup_auth_from_env_with_mapping():
    """Test setting up auth from environment with tool mapping."""
    env_vars = {
        "MCP_API_KEY": "test_api_key",
        "MCP_TOOL_AUTH_MAPPING": '{"tool1": "api_key", "tool2": "basic"}',
    }
    with patch.dict(os.environ, env_vars):
        auth_manager = setup_auth_from_env()

        assert "api_key" in auth_manager.auth_providers
        assert "tool1" in auth_manager.tool_auth_mapping
        assert "tool2" in auth_manager.tool_auth_mapping
        assert auth_manager.tool_auth_mapping["tool1"] == "api_key"
        assert auth_manager.tool_auth_mapping["tool2"] == "basic"


# Test cases for load_auth_config function
def test_load_auth_config_valid_file():
    """Test loading auth config from valid file."""
    config_data = {
        "providers": {
            "api_key": {
                "type": "api_key",
                "api_key": "test_key",
                "header_name": "X-API-Key",
            },
            "basic": {
                "type": "basic",
                "username": "test_user",
                "password": "test_password",
            },
        },
        "tool_mapping": {"tool1": "api_key", "tool2": "basic"},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_file = f.name

    try:
        auth_manager = load_auth_config(config_file)

        assert isinstance(auth_manager, AuthManager)
        assert "api_key" in auth_manager.auth_providers
        assert "basic" in auth_manager.auth_providers
        assert "tool1" in auth_manager.tool_auth_mapping
        assert "tool2" in auth_manager.tool_auth_mapping
    finally:
        os.unlink(config_file)


def test_load_auth_config_invalid_file():
    """Test loading auth config from invalid file."""
    with pytest.raises(FileNotFoundError):
        load_auth_config("nonexistent_file.json")


def test_load_auth_config_invalid_json():
    """Test loading auth config from invalid JSON file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("invalid json content")
        config_file = f.name

    try:
        with pytest.raises(json.JSONDecodeError):
            load_auth_config(config_file)
    finally:
        os.unlink(config_file)


def test_load_auth_config_missing_providers():
    """Test loading auth config with missing providers."""
    config_data = {"tool_mapping": {"tool1": "api_key"}}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_file = f.name

    try:
        auth_manager = load_auth_config(config_file)

        assert isinstance(auth_manager, AuthManager)
        assert auth_manager.auth_providers == {}
    finally:
        os.unlink(config_file)


def test_load_auth_config_unknown_provider_type():
    """Test loading auth config with unknown provider type."""
    config_data = {"providers": {"unknown": {"type": "unknown_type", "param": "value"}}}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_data, f)
        config_file = f.name

    try:
        with pytest.raises(ValueError) as excinfo:
            load_auth_config(config_file)

        assert "Unknown provider type" in str(excinfo.value)
    finally:
        os.unlink(config_file)


# Integration tests
def test_auth_provider_interface():
    """Test that all auth providers implement the interface."""
    providers = [
        APIKeyAuth("test_key"),
        BasicAuth("test_user", "test_password"),
        OAuthTokenAuth("test_token"),
        CustomHeaderAuth({"X-Header": "value"}),
    ]

    for provider in providers:
        # Test that they have the required methods
        assert hasattr(provider, "get_auth_headers")
        assert hasattr(provider, "get_auth_params")

        # Test that methods are callable
        assert callable(provider.get_auth_headers)
        assert callable(provider.get_auth_params)

        # Test that methods return dictionaries
        headers = provider.get_auth_headers()
        params = provider.get_auth_params()

        assert isinstance(headers, dict)
        assert isinstance(params, dict)


def test_auth_manager_integration():
    """Test AuthManager integration with different providers."""
    auth_manager = AuthManager()

    # Add different types of providers
    auth_manager.add_auth_provider("api_key", APIKeyAuth("test_key"))
    auth_manager.add_auth_provider("basic", BasicAuth("test_user", "test_password"))
    auth_manager.add_auth_provider("oauth", OAuthTokenAuth("test_token"))

    # Map tools to providers
    auth_manager.map_tool_to_auth("tool1", "api_key")
    auth_manager.map_tool_to_auth("tool2", "basic")
    auth_manager.map_tool_to_auth("tool3", "oauth")

    # Test getting auth for tools
    tool1_auth = auth_manager.get_auth_for_tool("tool1")
    tool2_auth = auth_manager.get_auth_for_tool("tool2")
    tool3_auth = auth_manager.get_auth_for_tool("tool3")

    assert isinstance(tool1_auth, APIKeyAuth)
    assert isinstance(tool2_auth, BasicAuth)
    assert isinstance(tool3_auth, OAuthTokenAuth)

    # Test getting headers
    tool1_headers = auth_manager.get_auth_headers_for_tool("tool1")
    tool2_headers = auth_manager.get_auth_headers_for_tool("tool2")
    tool3_headers = auth_manager.get_auth_headers_for_tool("tool3")

    assert "Authorization" in tool1_headers
    assert "Authorization" in tool2_headers
    assert "Authorization" in tool3_headers
