# Configuration File Loader

The MCP Fuzzer includes a powerful configuration file loader that allows you to define all your fuzzing settings in YAML files, eliminating the need to pass numerous command-line parameters.

## Overview

The configuration loader automatically discovers and loads configuration files from standard locations, supporting:

- **YAML format** (.yml or .yaml files)
- **Automatic discovery** from multiple locations
- **Environment variable overrides**
- **Custom transport definitions**
- **Authentication provider configurations**
- **Safety and output settings**

## Configuration File Discovery

The loader searches for configuration files in the following order:

1. **Explicit path** (if `--config` parameter is provided)
2. **Current directory**: `./mcp-fuzzer.yml` or `./mcp-fuzzer.yaml`
3. **User config directory**: `~/.config/mcp-fuzzer/mcp-fuzzer.yml`

## Basic Configuration Example

```yaml
# mcp-fuzzer.yaml
# General settings
timeout: 30.0
log_level: "INFO"
safety_enabled: true

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
```

## Using Configuration Files

### Command Line Usage

```bash
# Use default config file discovery
mcp-fuzzer

# Specify explicit config file
mcp-fuzzer --config /path/to/my-config.yaml

# Override config with command line (command line takes precedence)
mcp-fuzzer --config config.yaml --runs 20
```

### Automatic Loading

When you run `mcp-fuzzer` without any parameters, it automatically:

1. Searches for `mcp-fuzzer.yml` or `mcp-fuzzer.yaml` in current directory
2. Falls back to `~/.config/mcp-fuzzer/mcp-fuzzer.yml`
3. Loads and applies the configuration
4. Uses any remaining command-line arguments as overrides

## Configuration Sections

### Core Settings

```yaml
# Basic fuzzing parameters
timeout: 30.0                    # Default timeout in seconds
tool_timeout: 30.0              # Tool-specific timeout
log_level: "INFO"               # DEBUG, INFO, WARNING, ERROR, CRITICAL
safety_enabled: true            # Enable safety features
fs_root: "~/.mcp_fuzzer"        # Root directory for file operations

# Transport-specific timeouts
http_timeout: 30.0
sse_timeout: 30.0
stdio_timeout: 30.0
```

### Fuzzing Configuration

```yaml
# Fuzzing behavior
mode: "tools"                   # tools, protocol, both
phase: "aggressive"             # realistic, aggressive, both
protocol: "http"                # http, https, sse, stdio, streamablehttp
endpoint: "http://localhost:8000"
runs: 10                        # Number of fuzzing runs
runs_per_type: 5               # Runs per protocol type
protocol_type: "InitializeRequest"  # Specific protocol type to fuzz
max_concurrency: 5              # Maximum concurrent operations
```

### Safety Configuration

```yaml
safety:
  enabled: true
  no_network: false              # Disable network access
  local_hosts:                   # Allowed hosts for network operations
    - "localhost"
    - "127.0.0.1"
    - "::1"
  header_denylist:               # Headers to block
    - "authorization"
    - "cookie"
  proxy_env_denylist:            # Proxy environment variables to strip
    - "HTTP_PROXY"
    - "HTTPS_PROXY"
  env_allowlist: []              # Environment variables to allow
```

### Authentication Configuration

```yaml
auth:
  providers:
    - type: "api_key"
      id: "openai_api"
      config:
        key: "sk-your-openai-api-key"
        header_name: "Authorization"
    - type: "basic"
      id: "secure_api"
      config:
        username: "user"
        password: "password"
    - type: "oauth"
      id: "github_api"
      config:
        token: "ghp-your-github-token"
        header_name: "Authorization"

  mappings:
    "chat_completion": "openai_api"
    "github_search": "github_api"
    "secure_tool": "secure_api"
```

### Custom Transport Configuration

```yaml
custom_transports:
  my_websocket_transport:
    module: "my_transports.websocket"
    class: "WebSocketTransport"
    description: "Custom WebSocket transport for real-time communication"
    factory: "my_transports.create_websocket_transport"
    config_schema:
      type: "object"
      properties:
        url:
          type: "string"
          description: "WebSocket URL"
        timeout:
          type: "number"
          default: 30.0

  grpc_transport:
    module: "my_transports.grpc"
    class: "GRPCTransport"
    description: "gRPC transport for high-performance communication"
```

### Output Configuration

```yaml
output:
  format: "json"                 # json, yaml, csv, xml
  directory: "./reports"         # Output directory
  compress: true                 # Compress output files
  types:                         # Specific output types
    - "fuzzing_results"
    - "error_report"
    - "safety_summary"
    - "performance_metrics"
  retention:
    days: 30                     # Retain files for N days
    max_size: "1GB"              # Maximum directory size
```

## Advanced Examples

### Development Environment

```yaml
# development.yaml
timeout: 60.0
log_level: "DEBUG"
safety_enabled: false
mode: "tools"
phase: "realistic"
protocol: "stdio"
endpoint: "python test_server.py"
runs: 5
max_concurrency: 2

safety:
  enabled: false
  no_network: true
```

### Production Testing

```yaml
# production.yaml
timeout: 30.0
log_level: "WARNING"
safety_enabled: true
mode: "both"
phase: "aggressive"
protocol: "https"
endpoint: "https://api.production.com/mcp/"
runs: 50
max_concurrency: 10

safety:
  enabled: true
  no_network: false
  local_hosts: []
  header_denylist:
    - "authorization"
    - "cookie"
    - "x-api-key"

output:
  directory: "/var/log/mcp-fuzzer"
  compress: true
  retention:
    days: 90
    max_size: "10GB"
```

### CI/CD Pipeline

```yaml
# ci.yaml
timeout: 45.0
log_level: "INFO"
safety_enabled: true
mode: "tools"
phase: "realistic"
protocol: "http"
endpoint: "http://test-server:8000"
runs: 25
max_concurrency: 5

output:
  format: "json"
  directory: "./test-results"
  types:
    - "fuzzing_results"
    - "error_report"
    - "safety_summary"
```

## Environment Variable Overrides

You can override configuration values using environment variables:

```bash
# Override specific values
export MCP_FUZZER_TIMEOUT=60.0
export MCP_FUZZER_LOG_LEVEL=DEBUG
export MCP_FUZZER_SAFETY_ENABLED=false

# Run with config file + environment overrides
mcp-fuzzer --config production.yaml
```

## Configuration Validation

The configuration loader includes built-in validation:

- **Schema validation** against JSON Schema
- **Type checking** for all configuration values
- **Path validation** for file and directory paths
- **URL validation** for endpoints
- **Custom transport validation** for module/class existence

## Error Handling

The loader provides detailed error messages for common issues:

- **File not found**: Clear indication of search paths tried
- **YAML parsing errors**: Line numbers and context for syntax errors
- **Validation errors**: Specific field and constraint violations
- **Import errors**: Missing modules or classes for custom transports

## Best Practices

### Organization

1. **Use different configs for different environments**:
   - `development.yaml` - Relaxed settings for local development
   - `staging.yaml` - Production-like settings for testing
   - `production.yaml` - Strict settings for production systems

2. **Keep sensitive data separate**:
   - Use environment variables for API keys and passwords
   - Store config files with restricted permissions
   - Use secret management systems in production

### Version Control

1. **Commit base configurations** without sensitive data
2. **Use environment-specific overrides** for production values
3. **Document configuration options** in comments
4. **Version configuration files** with your application

### Security

1. **Restrict file permissions** on configuration files
2. **Use environment variables** for sensitive values
3. **Validate configuration** before use
4. **Audit configuration changes** in production

## Migration from Command Line

### Before (Command Line)

```bash
mcp-fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://localhost:8000 \
  --runs 10 \
  --phase aggressive \
  --timeout 30 \
  --log-level INFO \
  --enable-safety-system \
  --max-concurrency 5 \
  --output-dir ./reports
```

### After (Configuration File)

```yaml
# config.yaml
mode: "tools"
protocol: "http"
endpoint: "http://localhost:8000"
runs: 10
phase: "aggressive"
timeout: 30.0
log_level: "INFO"
safety_enabled: true
max_concurrency: 5

output:
  directory: "./reports"
```

```bash
# Simple command
mcp-fuzzer --config config.yaml
```

## Troubleshooting

### Common Issues

1. **Configuration not loading**:
   - Check file permissions
   - Verify YAML syntax
   - Ensure correct file extension (.yml or .yaml)

2. **Settings not applied**:
   - Command-line arguments override config file values
   - Check environment variable precedence
   - Verify configuration schema compliance

3. **Custom transport errors**:
   - Ensure module is in Python path
   - Verify class exists and inherits from TransportProtocol
   - Check factory function signature

### Debug Mode

Enable debug logging to troubleshoot configuration issues:

```bash
export MCP_FUZZER_LOG_LEVEL=DEBUG
mcp-fuzzer --config your-config.yaml
```

This will show detailed information about:
- Configuration file discovery
- Loading process
- Validation results
- Applied settings