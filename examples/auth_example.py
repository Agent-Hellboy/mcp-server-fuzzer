#!/usr/bin/env python3
"""
Authentication Example for MCP Fuzzer

This example demonstrates how to use authentication with the MCP fuzzer
for tools that require authentication.
"""

import asyncio
import os

from mcp_fuzzer.auth import (AuthManager, create_api_key_auth,
                             create_basic_auth, create_custom_header_auth,
                             create_oauth_auth, load_auth_config,
                             setup_auth_from_env)
from mcp_fuzzer.client import UnifiedMCPFuzzerClient
from mcp_fuzzer.transport import create_transport


async def example_with_manual_auth():
    """Example using manually configured authentication."""
    print("=== Manual Authentication Example ===")

    # Create auth manager
    auth_manager = AuthManager()

    # Add different auth providers
    auth_manager.add_auth_provider("openai", create_api_key_auth("sk-your-openai-key"))
    auth_manager.add_auth_provider("github", create_api_key_auth("ghp-your-github-token"))
    auth_manager.add_auth_provider("basic", create_basic_auth("user", "password"))
    auth_manager.add_auth_provider("oauth", create_oauth_auth("your-oauth-token"))
    auth_manager.add_auth_provider("custom", create_custom_header_auth({
        "X-API-Key": "your-custom-key",
        "X-Client-ID": "your-client-id"
    }))

    # Map tools to auth providers
    auth_manager.map_tool_to_auth("openai_chat", "openai")
    auth_manager.map_tool_to_auth("github_search", "github")
    auth_manager.map_tool_to_auth("secure_tool", "basic")
    auth_manager.map_tool_to_auth("oauth_tool", "oauth")
    auth_manager.map_tool_to_auth("custom_tool", "custom")

    # Create transport and client
    transport = create_transport("http", "http://localhost:8000")
    client = UnifiedMCPFuzzerClient(transport, auth_manager)

    print("Auth manager configured with multiple providers")
    print("Tool mappings:")
    for tool, provider in auth_manager.tool_auth_mapping.items():
        print(f"  {tool} -> {provider}")

    return client


async def example_with_env_auth():
    """Example using environment-based authentication."""
    print("\n=== Environment Authentication Example ===")

    # Set environment variables (in real usage, these would be set in your shell)
    os.environ["MCP_API_KEY"] = "sk-your-api-key-from-env"
    os.environ["MCP_USERNAME"] = "user"
    os.environ["MCP_PASSWORD"] = "password"
    os.environ["MCP_OAUTH_TOKEN"] = "your-oauth-token-from-env"

    # Create auth manager from environment
    auth_manager = setup_auth_from_env()

    # Map tools to auth providers
    auth_manager.map_tool_to_auth("api_tool", "default_api")
    auth_manager.map_tool_to_auth("basic_tool", "default_basic")
    auth_manager.map_tool_to_auth("oauth_tool", "default_oauth")

    # Create transport and client
    transport = create_transport("http", "http://localhost:8000")
    client = UnifiedMCPFuzzerClient(transport, auth_manager)

    print("Auth manager configured from environment variables")
    print("Available providers:", list(auth_manager.auth_providers.keys()))

    return client


async def example_with_config_file():
    """Example using configuration file-based authentication."""
    print("\n=== Config File Authentication Example ===")

    # Load auth config from file
    config_file = "examples/auth_config.json"
    auth_manager = load_auth_config(config_file)

    # Create transport and client
    transport = create_transport("http", "http://localhost:8000")
    client = UnifiedMCPFuzzerClient(transport, auth_manager)

    print(f"Auth manager configured from config file: {config_file}")
    print("Available providers:", list(auth_manager.auth_providers.keys()))
    print("Tool mappings:", auth_manager.tool_auth_mapping)

    return client


async def demonstrate_auth_usage():
    """Demonstrate how authentication is used during fuzzing."""
    print("\n=== Authentication Usage Demonstration ===")

    # Create a simple auth setup
    auth_manager = AuthManager()
    auth_manager.add_auth_provider("demo", create_api_key_auth("demo-key"))
    auth_manager.map_tool_to_auth("demo_tool", "demo")

    # transport = create_transport("http", "http://localhost:8000")  # Unused in this example
    # client = UnifiedMCPFuzzerClient(transport, auth_manager)  # Unused in this example

    # Simulate a tool that would be fuzzed
    # demo_tool = {  # Unused in this example
    #     "name": "demo_tool",
    #     "inputSchema": {
    #         "type": "object",
    #         "properties": {
    #             "message": {"type": "string"}
    #         }
    #     }
    # }

    print("When fuzzing 'demo_tool', the fuzzer will:")
    print("1. Generate random arguments based on the schema")
    print("2. Add authentication headers: {'Authorization': 'Bearer demo-key'}")
    print("3. Send the request with both fuzzed args and auth headers")

    # Show what auth headers would be used
    auth_headers = auth_manager.get_auth_headers_for_tool("demo_tool")
    print(f"Auth headers for demo_tool: {auth_headers}")


async def main():
    """Run all authentication examples."""
    print("MCP Fuzzer Authentication Examples")
    print("=" * 50)

    try:
        # Run examples
        await example_with_manual_auth()
        await example_with_env_auth()
        await example_with_config_file()
        await demonstrate_auth_usage()

        print("\n" + "=" * 50)
        print("Authentication examples completed successfully!")
        print("\nTo use authentication with the fuzzer:")
        print("1. Create an auth config file (see examples/auth_config.json)")
        print("2. Run: python -m mcp_fuzzer --auth-config path/to/config.json")
        print("3. Or use environment variables: python -m mcp_fuzzer --auth-env")

    except Exception as e:
        print(f"Error running examples: {e}")


if __name__ == "__main__":
    asyncio.run(main())
