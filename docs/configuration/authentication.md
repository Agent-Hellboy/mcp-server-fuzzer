# Authentication Guide

This guide explains how to configure authentication for MCP Server Fuzzer when testing servers that require authentication.

## Overview

MCP Server Fuzzer supports multiple authentication methods:
- **API Key** (Bearer Token)
- **Basic Authentication** (Username/Password)
- **OAuth** (Token-based)
- **Custom Authentication** (Custom headers)

## Quick Start

### Bearer Token Authentication

The most common authentication method for MCP servers is using a Bearer token. Here's how to configure it:

#### Using Configuration File

Create a `config.yaml` file:

```yaml
servers:
  my_server:
    protocol: http
    endpoint: "http://localhost:8080/mcp"
    runs: 10
    auth:
      type: api_key
      api_key: "your-token-here"
      header_name: "Authorization"
      prefix: "Bearer"
```

Run the fuzzer:

```bash
mcp-fuzzer --config config.yaml --server my_server
```

#### Using Auth Configuration File

Create an `auth_config.json` file:

```json
{
  "providers": {
    "my_auth": {
      "type": "api_key",
      "api_key": "your-token-here",
      "header_name": "Authorization",
      "prefix": "Bearer"
    }
  },
  "tool_mappings": {}
}
```

Run the fuzzer:

```bash
mcp-fuzzer --mode tools --protocol http \
  --endpoint "http://localhost:8080/mcp" \
  --auth-config auth_config.json \
  --runs 10
```

#### Using Environment Variables

Set environment variables:

```bash
export MCP_API_KEY="your-token-here"
export MCP_HEADER_NAME="Authorization"
export MCP_PREFIX="Bearer"
```

Run the fuzzer:

```bash
mcp-fuzzer --mode tools --protocol http \
  --endpoint "http://localhost:8080/mcp" \
  --auth-env \
  --runs 10
```

## Authentication Methods

### 1. API Key Authentication (Bearer Token)

API Key authentication sends a token in the request headers.

**Configuration File (`config.yaml`):**

```yaml
servers:
  api_server:
    protocol: http
    endpoint: "https://api.example.com/mcp"
    runs: 50
    auth:
      type: api_key
      api_key: "${API_KEY}"  # Use environment variable
      header_name: "Authorization"
      prefix: "Bearer"  # Optional, defaults to "Bearer"
```

**Auth Config File (`auth_config.json`):**

```json
{
  "providers": {
    "api_key_provider": {
      "type": "api_key",
      "api_key": "your-api-key-here",
      "header_name": "Authorization",
      "prefix": "Bearer"
    }
  },
  "tool_mappings": {
    "secure_tool": "api_key_provider"
  }
}
```

**Environment Variables:**

```bash
export MCP_API_KEY="your-api-key-here"
export MCP_HEADER_NAME="Authorization"
export MCP_PREFIX="Bearer"
```

### 2. Basic Authentication

Basic authentication uses a username and password.

**Configuration File:**

```yaml
servers:
  basic_auth_server:
    protocol: http
    endpoint: "https://api.example.com/mcp"
    runs: 50
    auth:
      type: basic
      username: "${USERNAME}"
      password: "${PASSWORD}"
```

**Auth Config File:**

```json
{
  "providers": {
    "basic_auth_provider": {
      "type": "basic",
      "username": "your-username",
      "password": "your-password"
    }
  }
}
```

**Environment Variables:**

```bash
export MCP_USERNAME="your-username"
export MCP_PASSWORD="your-password"
```

### 3. OAuth Authentication

OAuth authentication uses an access token.

**Configuration File:**

```yaml
servers:
  oauth_server:
    protocol: http
    endpoint: "https://api.example.com/mcp"
    runs: 50
    auth:
      type: oauth
      token: "${OAUTH_TOKEN}"
      header_name: "Authorization"  # Optional, defaults to "Authorization"
```

**Auth Config File:**

```json
{
  "providers": {
    "oauth_provider": {
      "type": "oauth",
      "token": "your-oauth-token",
      "header_name": "Authorization"
    }
  }
}
```

**Environment Variables:**

```bash
export MCP_OAUTH_TOKEN="your-oauth-token"
```

### 4. Custom Authentication

For custom authentication requirements, you can specify custom headers.

**Configuration File:**

```yaml
servers:
  custom_auth_server:
    protocol: http
    endpoint: "https://api.example.com/mcp"
    runs: 50
    auth:
      type: custom
      headers:
        X-API-Key: "${CUSTOM_API_KEY}"
        X-Custom-Header: "custom-value"
```

**Auth Config File:**

```json
{
  "providers": {
    "custom_provider": {
      "type": "custom",
      "headers": {
        "X-API-Key": "your-custom-key",
        "X-Custom-Header": "custom-value"
      }
    }
  }
}
```

## Per-Tool Authentication

You can configure different authentication for specific tools using tool mappings.

**Auth Config File:**

```json
{
  "providers": {
    "provider_a": {
      "type": "api_key",
      "api_key": "key-for-provider-a",
      "header_name": "Authorization",
      "prefix": "Bearer"
    },
    "provider_b": {
      "type": "basic",
      "username": "user-b",
      "password": "pass-b"
    }
  },
  "tool_mappings": {
    "secure_tool_1": "provider_a",
    "secure_tool_2": "provider_a",
    "admin_tool": "provider_b"
  }
}
```

## Configuration Priority

Authentication configuration is merged in the following order (highest to lowest priority):

1. **Command-line arguments** (highest priority)
2. **Configuration file** (--config)
3. **Auth configuration file** (--auth-config)
4. **Environment variables** (lowest priority)

## Common Issues and Solutions

### Issue: "HTTP 401: Unauthorized" or "no bearer token"

**Solution:** Ensure your authentication configuration is correctly formatted.

For Bearer tokens, make sure to include the `prefix` field:

```json
{
  "providers": {
    "my_auth": {
      "type": "api_key",
      "api_key": "your-token",
      "header_name": "Authorization",
      "prefix": "Bearer"
    }
  }
}
```

### Issue: "--server argument not recognized" when using --config

**Solution:** When using a configuration file, specify the server name directly:

```bash
# Correct
mcp-fuzzer --config config.yaml --server my_server

# If your config has default server settings at root level, use:
mcp-fuzzer --config config.yaml
```

### Issue: "unrecognized arguments: --server" error

**Solution:** This usually means the config file structure is incorrect. Ensure your config file has a `servers` section:

```yaml
servers:
  my_server:
    protocol: http
    endpoint: "http://localhost:8080/mcp"
    runs: 10
    auth:
      type: api_key
      api_key: "your-token"
      header_name: "Authorization"
      prefix: "Bearer"
```

### Issue: Confusing error messages like "Unexpected error: 'api_key'"

**Solution:** This indicates a malformed auth configuration. Check that:

1. All required fields are present for your auth type
2. Field names are spelled correctly
3. The JSON/YAML syntax is valid

**Valid auth_config.json structure:**

```json
{
  "providers": {
    "provider_name": {
      "type": "api_key",
      "api_key": "value",
      "header_name": "Authorization",
      "prefix": "Bearer"
    }
  },
  "tool_mappings": {}
}
```

## Examples

### Example 1: Bearer Token with Config File

```yaml
# config.yaml
servers:
  local_server:
    protocol: http
    endpoint: "http://localhost:8080/mcp"
    runs: 10
    phase: both
    timeout: 30.0
    auth:
      type: api_key
      api_key: "my-secret-token"
      header_name: "Authorization"
      prefix: "Bearer"
```

```bash
mcp-fuzzer --config config.yaml --server local_server
```

### Example 2: Multiple Authentication Providers

```yaml
# config.yaml
servers:
  prod_api:
    protocol: http
    endpoint: "https://api.prod.com/mcp"
    runs: 50
    auth:
      type: api_key
      api_key: "${PROD_API_KEY}"
      header_name: "Authorization"
      prefix: "Bearer"

  admin_api:
    protocol: http
    endpoint: "https://admin.prod.com/mcp"
    runs: 20
    auth:
      type: basic
      username: "${ADMIN_USER}"
      password: "${ADMIN_PASS}"
```

```bash
# Set environment variables
export PROD_API_KEY="prod-key-123"
export ADMIN_USER="admin"
export ADMIN_PASS="secure-password"

# Test production API
mcp-fuzzer --config config.yaml --server prod_api

# Test admin API
mcp-fuzzer --config config.yaml --server admin_api
```

### Example 3: Environment Variables Only

```bash
# Set authentication
export MCP_API_KEY="your-bearer-token"
export MCP_HEADER_NAME="Authorization"
export MCP_PREFIX="Bearer"

# Run fuzzer
mcp-fuzzer --mode tools \
  --protocol http \
  --endpoint "http://localhost:8080/mcp" \
  --auth-env \
  --runs 10 \
  --phase both
```

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use environment variables** for sensitive tokens in configuration files
3. **Rotate tokens regularly** when testing production-like environments
4. **Use separate credentials** for testing vs. production
5. **Store auth configs** outside of the project directory
6. **Set appropriate permissions** on auth config files:
   ```bash
   chmod 600 auth_config.json
   ```

## Debugging Authentication

Enable verbose logging to see authentication details:

```bash
mcp-fuzzer --mode tools \
  --protocol http \
  --endpoint "http://localhost:8080/mcp" \
  --auth-config auth_config.json \
  --verbose \
  --log-level DEBUG \
  --runs 1
```

This will show:
- Headers being sent
- Authentication provider selection
- Token/credential resolution
- HTTP request/response details

## Getting Help

If you're still experiencing issues:

1. Check the [Configuration Guide](configuration.md)
2. Review [error codes documentation](../error-codes.md)
3. Enable debug logging: `--verbose --log-level DEBUG`
4. Open an issue on [GitHub](https://github.com/Agent-Hellboy/mcp-server-fuzzer/issues) with:
   - Your config file (redact secrets!)
   - Error messages
   - Debug logs
   - MCP server type (if known)
