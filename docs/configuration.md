# Configuration Guide

MCP Fuzzer provides flexible configuration options to customize its behavior. This guide explains the various ways to configure the fuzzer and how to handle configuration errors.

## Configuration Precedence

MCP Fuzzer uses the following precedence order when determining configuration values (highest to lowest):

1. Command-line arguments
2. Configuration files (specified with `--config`)
3. Default configuration files (searched in standard locations)
4. Environment variables
5. Built-in defaults

## Configuration Files

MCP Fuzzer supports YAML configuration files with either `.yml` or `.yaml` extensions.

### Specifying a Configuration File

You can specify a configuration file using the `--config` option:

```bash
mcp-fuzzer --config path/to/mcp-fuzzer.yml
```

### Default Configuration Locations

If no configuration file is specified, MCP Fuzzer will search for a configuration file in the following locations:

1. Current working directory
2. User's configuration directory (`~/.config/mcp-fuzzer/`)

The recognized file names are:
- `mcp-fuzzer.yml`
- `mcp-fuzzer.yaml`

### Example YAML Configuration

```yaml
# General settings
timeout: 30.0
log_level: "INFO"

# Transport settings
http_timeout: 30.0
sse_timeout: 30.0
stdio_timeout: 30.0

# Fuzzing settings
mode: "both"
phase: "aggressive"
protocol: "http"
endpoint: "http://localhost:8000/mcp/"
runs: 10
runs_per_type: 5
max_concurrency: 5

# Safety settings
safety:
  enabled: true
  no_network: false
  local_hosts:
    - "localhost"
    - "127.0.0.1"
    - "::1"
  header_denylist:
    - "authorization"
    - "cookie"

# Authentication settings
auth:
  providers:
    - type: "api_key"
      id: "default_api_key"
      config:
        key: "YOUR_API_KEY"
        header_name: "X-API-Key"
    - type: "basic"
      id: "default_basic"
      config:
        username: "user"
        password: "pass"
  mappings:
    "tool1": "default_api_key"
    "tool2": "default_basic"
```

A complete example configuration file is available in the `examples/config/` directory.

## Environment Variables

MCP Fuzzer can also be configured using environment variables:

```bash
# Core configuration
export MCP_FUZZER_TIMEOUT=30.0
export MCP_FUZZER_LOG_LEVEL=INFO
export MCP_FUZZER_SAFETY_ENABLED=true

# Transport configuration
export MCP_FUZZER_HTTP_TIMEOUT=30.0
export MCP_FUZZER_SSE_TIMEOUT=30.0
export MCP_FUZZER_STDIO_TIMEOUT=30.0

# Safety configuration
export MCP_FUZZER_FS_ROOT=~/.mcp_fuzzer
```

## Error Handling

MCP Fuzzer provides a comprehensive error handling system for configuration-related errors:

### Configuration Error Types

- `ConfigurationError`: Base exception for all configuration-related errors
- `ConfigFileError`: Raised when there are issues with configuration files (not found, invalid format, parsing errors)
- `ValidationError`: Raised when configuration validation fails

### Common Error Scenarios

- **File Not Found**: When the specified configuration file doesn't exist
- **Invalid Format**: When the file extension is not supported (only .yml and .yaml are supported)
- **Parsing Error**: When the YAML content cannot be parsed
- **Permission Error**: When there are permission issues reading the file

### Example Error Handling

```python
from mcp_fuzzer.exceptions import ConfigFileError, ValidationError

try:
    # Attempt to load configuration
    from mcp_fuzzer.config_loader import load_config_file
    config_data = load_config_file("path/to/config.yml")
except ConfigFileError as e:
    print(f"Configuration file error: {e}")
    # Handle file-related errors
except ValidationError as e:
    print(f"Configuration validation error: {e}")
    # Handle validation errors
```

## Configuration Schema

The following table describes the available configuration options:

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `timeout` | float | Default timeout in seconds | 30.0 |
| `tool_timeout` | float | Tool-specific timeout in seconds | 30.0 |
| `log_level` | string | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | INFO |
| `safety.enabled` | boolean | Whether safety features are enabled | true |
| `fs_root` | string | Root directory for file operations | ~/.mcp_fuzzer |
| `http_timeout` | float | HTTP transport timeout in seconds | 30.0 |
| `sse_timeout` | float | SSE transport timeout in seconds | 30.0 |
| `stdio_timeout` | float | STDIO transport timeout in seconds | 30.0 |
| `mode` | string | Fuzzing mode (tools, protocol, both) | both |
| `phase` | string | Fuzzing phase (realistic, aggressive, both) | aggressive |
| `protocol` | string | Transport protocol (http, sse, stdio) | http |
| `endpoint` | string | Server endpoint URL | - |
| `runs` | integer | Number of fuzzing runs | 10 |
| `runs_per_type` | integer | Number of runs per protocol type | 5 |
| `protocol_type` | string | Specific protocol type to fuzz | - |
| `safety.no_network` | boolean | Disable network access | false |
| `safety.local_hosts` | array | List of allowed hosts | ["localhost", "127.0.0.1", "::1"] |
| `safety.header_denylist` | array | Headers to strip/deny | ["authorization","cookie"] |
| `safety.proxy_env_denylist` | array | Proxy env vars to ignore | ["HTTP_PROXY","HTTPS_PROXY"] |
| `safety.env_allowlist` | array | Env vars allowed to pass through | [] |
| `max_concurrency` | integer | Maximum concurrent operations | 5 |

### Nested Configuration

Some configuration options use nested structures:

#### Safety Configuration

```yaml
safety:
  enabled: true
  no_network: false
  local_hosts:
    - "localhost"
    - "127.0.0.1"
    - "::1"
  header_denylist:
    - "authorization"
    - "cookie"
  proxy_env_denylist:
    - "HTTP_PROXY"
    - "HTTPS_PROXY"
  env_allowlist: []
```

#### Authentication Configuration

```yaml
auth:
  providers:
    - type: "api_key"
      id: "default_api_key"
      config:
        key: "YOUR_API_KEY"
        header_name: "X-API-Key"
  mappings:
    "tool1": "default_api_key"
```
