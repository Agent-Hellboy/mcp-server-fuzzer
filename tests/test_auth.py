#!/usr/bin/env python3
"""
Unit tests for Auth module
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

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


class TestAuthProvider(unittest.TestCase):
    """Test cases for AuthProvider base class."""

    def test_auth_provider_abstract(self):
        """Test that AuthProvider is properly abstract."""
        # Should not be able to instantiate AuthProvider directly
        with self.assertRaises(TypeError):
            AuthProvider()


class TestAPIKeyAuth(unittest.TestCase):
    """Test cases for APIKeyAuth class."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth = APIKeyAuth("test_api_key", "X-API-Key")

    def test_init(self):
        """Test APIKeyAuth initialization."""
        self.assertEqual(self.auth.api_key, "test_api_key")
        self.assertEqual(self.auth.header_name, "X-API-Key")

    def test_init_default_header(self):
        """Test APIKeyAuth initialization with default header."""
        auth = APIKeyAuth("test_api_key")
        self.assertEqual(auth.header_name, "Authorization")

    def test_get_auth_headers(self):
        """Test getting auth headers."""
        headers = self.auth.get_auth_headers()

        self.assertIn("X-API-Key", headers)
        self.assertEqual(headers["X-API-Key"], "Bearer test_api_key")

    def test_get_auth_headers_default_header(self):
        """Test getting auth headers with default header."""
        auth = APIKeyAuth("test_api_key")
        headers = auth.get_auth_headers()

        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer test_api_key")

    def test_get_auth_params(self):
        """Test getting auth params."""
        params = self.auth.get_auth_params()

        self.assertEqual(params, {})


class TestBasicAuth(unittest.TestCase):
    """Test cases for BasicAuth class."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth = BasicAuth("test_user", "test_password")

    def test_init(self):
        """Test BasicAuth initialization."""
        self.assertEqual(self.auth.username, "test_user")
        self.assertEqual(self.auth.password, "test_password")

    def test_get_auth_headers(self):
        """Test getting auth headers."""
        headers = self.auth.get_auth_headers()

        self.assertIn("Authorization", headers)
        # Check that the credentials are base64 encoded
        self.assertTrue(headers["Authorization"].startswith("Basic "))

        # Decode and verify the credentials
        import base64

        encoded_credentials = headers["Authorization"].replace("Basic ", "")
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        self.assertEqual(decoded_credentials, "test_user:test_password")

    def test_get_auth_params(self):
        """Test getting auth params."""
        params = self.auth.get_auth_params()

        self.assertEqual(params, {})


class TestOAuthTokenAuth(unittest.TestCase):
    """Test cases for OAuthTokenAuth class."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth = OAuthTokenAuth("test_token", "Bearer")

    def test_init(self):
        """Test OAuthTokenAuth initialization."""
        self.assertEqual(self.auth.token, "test_token")
        self.assertEqual(self.auth.token_type, "Bearer")

    def test_init_default_token_type(self):
        """Test OAuthTokenAuth initialization with default token type."""
        auth = OAuthTokenAuth("test_token")
        self.assertEqual(auth.token_type, "Bearer")

    def test_get_auth_headers(self):
        """Test getting auth headers."""
        headers = self.auth.get_auth_headers()

        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer test_token")

    def test_get_auth_headers_custom_token_type(self):
        """Test getting auth headers with custom token type."""
        auth = OAuthTokenAuth("test_token", "Token")
        headers = auth.get_auth_headers()

        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Token test_token")

    def test_get_auth_params(self):
        """Test getting auth params."""
        params = self.auth.get_auth_params()

        self.assertEqual(params, {})


class TestCustomHeaderAuth(unittest.TestCase):
    """Test cases for CustomHeaderAuth class."""

    def setUp(self):
        """Set up test fixtures."""
        self.headers = {"X-Custom-Header": "custom_value", "X-API-Key": "api_key_value"}
        self.auth = CustomHeaderAuth(self.headers)

    def test_init(self):
        """Test CustomHeaderAuth initialization."""
        self.assertEqual(self.auth.headers, self.headers)

    def test_get_auth_headers(self):
        """Test getting auth headers."""
        headers = self.auth.get_auth_headers()

        self.assertEqual(headers, self.headers)
        self.assertIn("X-Custom-Header", headers)
        self.assertIn("X-API-Key", headers)
        self.assertEqual(headers["X-Custom-Header"], "custom_value")
        self.assertEqual(headers["X-API-Key"], "api_key_value")

    def test_get_auth_params(self):
        """Test getting auth params."""
        params = self.auth.get_auth_params()

        self.assertEqual(params, {})


class TestAuthManager(unittest.TestCase):
    """Test cases for AuthManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.auth_manager = AuthManager()

    def test_init(self):
        """Test AuthManager initialization."""
        self.assertEqual(self.auth_manager.auth_providers, {})
        self.assertEqual(self.auth_manager.tool_auth_mapping, {})

    def test_add_auth_provider(self):
        """Test adding auth provider."""
        auth_provider = APIKeyAuth("test_key")
        self.auth_manager.add_auth_provider("test_provider", auth_provider)

        self.assertIn("test_provider", self.auth_manager.auth_providers)
        self.assertEqual(
            self.auth_manager.auth_providers["test_provider"], auth_provider
        )

    def test_map_tool_to_auth(self):
        """Test mapping tool to auth provider."""
        self.auth_manager.map_tool_to_auth("test_tool", "test_provider")

        self.assertIn("test_tool", self.auth_manager.tool_auth_mapping)
        self.assertEqual(
            self.auth_manager.tool_auth_mapping["test_tool"], "test_provider"
        )

    def test_get_auth_for_tool_mapped(self):
        """Test getting auth for mapped tool."""
        auth_provider = APIKeyAuth("test_key")
        self.auth_manager.add_auth_provider("test_provider", auth_provider)
        self.auth_manager.map_tool_to_auth("test_tool", "test_provider")

        result = self.auth_manager.get_auth_for_tool("test_tool")

        self.assertEqual(result, auth_provider)

    def test_get_auth_for_tool_not_mapped(self):
        """Test getting auth for unmapped tool."""
        result = self.auth_manager.get_auth_for_tool("test_tool")

        self.assertIsNone(result)

    def test_get_auth_headers_for_tool_mapped(self):
        """Test getting auth headers for mapped tool."""
        auth_provider = APIKeyAuth("test_key", "X-API-Key")
        self.auth_manager.add_auth_provider("test_provider", auth_provider)
        self.auth_manager.map_tool_to_auth("test_tool", "test_provider")

        headers = self.auth_manager.get_auth_headers_for_tool("test_tool")

        self.assertIn("X-API-Key", headers)
        self.assertEqual(headers["X-API-Key"], "Bearer test_key")

    def test_get_auth_headers_for_tool_not_mapped(self):
        """Test getting auth headers for unmapped tool."""
        headers = self.auth_manager.get_auth_headers_for_tool("test_tool")

        self.assertEqual(headers, {})

    def test_get_auth_params_for_tool_mapped(self):
        """Test getting auth params for mapped tool."""
        auth_provider = APIKeyAuth("test_key")
        self.auth_manager.add_auth_provider("test_provider", auth_provider)
        self.auth_manager.map_tool_to_auth("test_tool", "test_provider")

        params = self.auth_manager.get_auth_params_for_tool("test_tool")

        self.assertEqual(params, {})

    def test_get_auth_params_for_tool_not_mapped(self):
        """Test getting auth params for unmapped tool."""
        params = self.auth_manager.get_auth_params_for_tool("test_tool")

        self.assertEqual(params, {})


class TestAuthFactoryFunctions(unittest.TestCase):
    """Test cases for auth factory functions."""

    def test_create_api_key_auth(self):
        """Test creating API key auth."""
        auth = create_api_key_auth("test_key", "X-API-Key")

        self.assertIsInstance(auth, APIKeyAuth)
        self.assertEqual(auth.api_key, "test_key")
        self.assertEqual(auth.header_name, "X-API-Key")

    def test_create_basic_auth(self):
        """Test creating basic auth."""
        auth = create_basic_auth("test_user", "test_password")

        self.assertIsInstance(auth, BasicAuth)
        self.assertEqual(auth.username, "test_user")
        self.assertEqual(auth.password, "test_password")

    def test_create_oauth_auth(self):
        """Test creating OAuth auth."""
        auth = create_oauth_auth("test_token", "Bearer")

        self.assertIsInstance(auth, OAuthTokenAuth)
        self.assertEqual(auth.token, "test_token")
        self.assertEqual(auth.token_type, "Bearer")

    def test_create_custom_header_auth(self):
        """Test creating custom header auth."""
        headers = {"X-Custom-Header": "custom_value"}
        auth = create_custom_header_auth(headers)

        self.assertIsInstance(auth, CustomHeaderAuth)
        self.assertEqual(auth.headers, headers)


class TestSetupAuthFromEnv(unittest.TestCase):
    """Test cases for setup_auth_from_env function."""

    @patch.dict(
        os.environ,
        {
            "MCP_API_KEY": "test_api_key",
            "MCP_USERNAME": "test_user",
            "MCP_PASSWORD": "test_password",
            "MCP_OAUTH_TOKEN": "test_token",
            "MCP_CUSTOM_HEADERS": '{"X-Custom": "value"}',
        },
    )
    def test_setup_auth_from_env_all_providers(self):
        """Test setting up auth from environment with all providers."""
        auth_manager = setup_auth_from_env()

        self.assertIsInstance(auth_manager, AuthManager)
        self.assertIn("api_key", auth_manager.auth_providers)
        self.assertIn("basic", auth_manager.auth_providers)
        self.assertIn("oauth", auth_manager.auth_providers)
        self.assertIn("custom", auth_manager.auth_providers)

    @patch.dict(os.environ, {}, clear=True)
    def test_setup_auth_from_env_no_vars(self):
        """Test setting up auth from environment with no variables."""
        auth_manager = setup_auth_from_env()

        self.assertIsInstance(auth_manager, AuthManager)
        self.assertEqual(auth_manager.auth_providers, {})

    @patch.dict(
        os.environ,
        {
            "MCP_API_KEY": "test_api_key",
            "MCP_TOOL_AUTH_MAPPING": '{"tool1": "api_key", "tool2": "basic"}',
        },
    )
    def test_setup_auth_from_env_with_mapping(self):
        """Test setting up auth from environment with tool mapping."""
        auth_manager = setup_auth_from_env()

        self.assertIn("api_key", auth_manager.auth_providers)
        self.assertIn("tool1", auth_manager.tool_auth_mapping)
        self.assertIn("tool2", auth_manager.tool_auth_mapping)
        self.assertEqual(auth_manager.tool_auth_mapping["tool1"], "api_key")
        self.assertEqual(auth_manager.tool_auth_mapping["tool2"], "basic")


class TestLoadAuthConfig(unittest.TestCase):
    """Test cases for load_auth_config function."""

    def test_load_auth_config_valid_file(self):
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

            self.assertIsInstance(auth_manager, AuthManager)
            self.assertIn("api_key", auth_manager.auth_providers)
            self.assertIn("basic", auth_manager.auth_providers)
            self.assertIn("tool1", auth_manager.tool_auth_mapping)
            self.assertIn("tool2", auth_manager.tool_auth_mapping)
        finally:
            os.unlink(config_file)

    def test_load_auth_config_invalid_file(self):
        """Test loading auth config from invalid file."""
        with self.assertRaises(FileNotFoundError):
            load_auth_config("nonexistent_file.json")

    def test_load_auth_config_invalid_json(self):
        """Test loading auth config from invalid JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            config_file = f.name

        try:
            with self.assertRaises(json.JSONDecodeError):
                load_auth_config(config_file)
        finally:
            os.unlink(config_file)

    def test_load_auth_config_missing_providers(self):
        """Test loading auth config with missing providers."""
        config_data = {"tool_mapping": {"tool1": "api_key"}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            auth_manager = load_auth_config(config_file)

            self.assertIsInstance(auth_manager, AuthManager)
            self.assertEqual(auth_manager.auth_providers, {})
        finally:
            os.unlink(config_file)

    def test_load_auth_config_unknown_provider_type(self):
        """Test loading auth config with unknown provider type."""
        config_data = {
            "providers": {"unknown": {"type": "unknown_type", "param": "value"}}
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            with self.assertRaises(ValueError) as context:
                load_auth_config(config_file)

            self.assertIn("Unknown provider type", str(context.exception))
        finally:
            os.unlink(config_file)


class TestAuthIntegration(unittest.TestCase):
    """Integration tests for auth modules."""

    def test_auth_provider_interface(self):
        """Test that all auth providers implement the interface."""
        providers = [
            APIKeyAuth("test_key"),
            BasicAuth("test_user", "test_password"),
            OAuthTokenAuth("test_token"),
            CustomHeaderAuth({"X-Header": "value"}),
        ]

        for provider in providers:
            # Test that they have the required methods
            self.assertTrue(hasattr(provider, "get_auth_headers"))
            self.assertTrue(hasattr(provider, "get_auth_params"))

            # Test that methods are callable
            self.assertTrue(callable(provider.get_auth_headers))
            self.assertTrue(callable(provider.get_auth_params))

            # Test that methods return dictionaries
            headers = provider.get_auth_headers()
            params = provider.get_auth_params()

            self.assertIsInstance(headers, dict)
            self.assertIsInstance(params, dict)

    def test_auth_manager_integration(self):
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

        self.assertIsInstance(tool1_auth, APIKeyAuth)
        self.assertIsInstance(tool2_auth, BasicAuth)
        self.assertIsInstance(tool3_auth, OAuthTokenAuth)

        # Test getting headers
        tool1_headers = auth_manager.get_auth_headers_for_tool("tool1")
        tool2_headers = auth_manager.get_auth_headers_for_tool("tool2")
        tool3_headers = auth_manager.get_auth_headers_for_tool("tool3")

        self.assertIn("Authorization", tool1_headers)
        self.assertIn("Authorization", tool2_headers)
        self.assertIn("Authorization", tool3_headers)


if __name__ == "__main__":
    unittest.main()
