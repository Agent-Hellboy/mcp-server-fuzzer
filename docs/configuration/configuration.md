# Configuration Guide

This guide provides comprehensive information on configuring MCP Server Fuzzer using configuration files, environment variables, and command-line arguments.

## Configuration Methods

MCP Server Fuzzer supports multiple configuration methods in order of precedence:

1. **Command-line arguments** (highest precedence)
2. **Configuration files** (YAML/TOML)
3. **Environment variables** (lowest precedence)

### When to Use Configuration Files vs Command-Line Arguments

While command-line arguments provide quick access to common options, configuration files are recommended for:

- **Complex configurations** with many parameters
- **Reproducible setups** across different environments
- **Team sharing** of standardized configurations
- **Advanced features** not exposed as CLI flags
- **Security** by keeping sensitive values in files rather than command history

If you find yourself using many command-line flags repeatedly, consider creating a configuration file instead. The CLI currently supports 42 flags - for configurations requiring more customization, use YAML/TOML files to maintain readability and maintainability.

## Configuration Files

### YAML Configuration

Create a `mcp-fuzzer.yaml` or `mcp-fuzzer.yml` file:

```yaml
# Global settings
global:
  timeout: 30.0
  log_level: INFO
  verbose: false
  output_dir: "reports"

# Safety system configuration
safety:
  enabled: true
  fs_root: "~/.mcp_fuzzer"
  retry_with_safety_on_interrupt: false

# Runtime configuration
runtime:
  max_concurrency: 5

# Watchdog configuration
watchdog:
  check_interval: 1.0
  process_timeout: 30.0
  extra_buffer: 5.0
  max_hang_time: 60.0
  auto_kill: true

# Transport-specific settings
transports:
  http:
    timeout: 30.0
    verify_ssl: true
    max_retries: 3

  sse:
    timeout: 30.0
    reconnect_interval: 5.0

  stdio:
    timeout: 30.0
    buffer_size: 4096

# Server configurations
servers:
  local_http:
    protocol: http
    endpoint: "http://localhost:8000"
    runs: 10
    phase: aggressive

  local_stdio:
    protocol: stdio
    endpoint: "python test_server.py"
    runs: 5
    phase: realistic
    safety:
      enabled: true
      fs_root: "/tmp/safe_dir"

  production_api:
    protocol: http
    endpoint: "https://api.example.com"
    runs: 20
    phase: realistic
    timeout: 60.0
    auth:
      type: api_key
      api_key: "${API_KEY}"
      header_name: "Authorization"

# Authentication providers
auth:
  providers:
    openai_api:
      type: api_key
      api_key: "${OPENAI_API_KEY}"
      header_name: "Authorization"

    github_api:
      type: api_key
      api_key: "${GITHUB_TOKEN}"
      header_name: "Authorization"

    basic_auth:
      type: basic
      username: "${USERNAME}"
      password: "${PASSWORD}"

tool_mapping:
    openai_chat: openai_api
    github_search: github_api
    secure_tool: basic_auth

# Reporting configuration
reporting:
  enable_console: true
  enable_json: true
  enable_text: true
  safety_report: false
  export_safety_data: false
  custom_formatters:
    - name: "csv"
      enabled: true
      output_file: "results.csv"
    - name: "xml"
      enabled: false
      output_file: "results.xml"
```

### TOML Configuration

Create a `mcp-fuzzer.toml` file:

```toml
# Global settings
[global]
timeout = 30.0
log_level = "INFO"
verbose = false
output_dir = "reports"

# Safety system configuration
[safety]
enabled = true
fs_root = "~/.mcp_fuzzer"
retry_with_safety_on_interrupt = false

# Runtime configuration
[runtime]
max_concurrency = 5

# Watchdog configuration
[watchdog]
check_interval = 1.0
process_timeout = 30.0
extra_buffer = 5.0
max_hang_time = 60.0
auto_kill = true

# Transport-specific settings
[transports.http]
timeout = 30.0
verify_ssl = true
max_retries = 3

[transports.sse]
timeout = 30.0
reconnect_interval = 5.0

[transports.stdio]
timeout = 30.0
buffer_size = 4096

# Server configurations
[servers.local_http]
protocol = "http"
endpoint = "http://localhost:8000"
runs = 10
phase = "aggressive"

[servers.local_stdio]
protocol = "stdio"
endpoint = "python test_server.py"
runs = 5
phase = "realistic"

[servers.local_stdio.safety]
enabled = true
fs_root = "/tmp/safe_dir"

[servers.production_api]
protocol = "http"
endpoint = "https://api.example.com"
runs = 20
phase = "realistic"
timeout = 60.0

[servers.production_api.auth]
type = "api_key"
api_key = "${API_KEY}"
header_name = "Authorization"

# Authentication providers
[auth.providers.openai_api]
type = "api_key"
api_key = "${OPENAI_API_KEY}"
header_name = "Authorization"

[auth.providers.github_api]
type = "api_key"
api_key = "${GITHUB_TOKEN}"
header_name = "Authorization"

[auth.providers.basic_auth]
type = "basic"
username = "${USERNAME}"
password = "${PASSWORD}"

[auth.tool_mapping]
openai_chat = "openai_api"
github_search = "github_api"
secure_tool = "basic_auth"

# Reporting configuration
[reporting]
enable_console = true
enable_json = true
enable_text = true
safety_report = false
export_safety_data = false

[reporting.custom_formatters.csv]
enabled = true
output_file = "results.csv"

[reporting.custom_formatters.xml]
enabled = false
output_file = "results.xml"
```

## Using Configuration Files

### Command Line Usage

```bash
# Use default configuration file (mcp-fuzzer.yaml or mcp-fuzzer.toml)
mcp-fuzzer --mode tools --server local_http

# Specify custom configuration file
mcp-fuzzer --mode tools --config custom-config.yaml --server local_http

# Override configuration with command-line arguments
mcp-fuzzer --mode tools --config config.yaml --server local_http --runs 50 --verbose
```

### Environment Variable Substitution

Configuration files support environment variable substitution:

```yaml
servers:
  production_api:
    protocol: http
    endpoint: "https://${API_HOST}:${API_PORT}"
    auth:
      api_key: "${API_KEY}"
```

```bash
# Set environment variables
export API_HOST="api.example.com"
export API_PORT="443"
export API_KEY="your-api-key"

# Use configuration
mcp-fuzzer --mode tools --config config.yaml --server production_api
```

## Environment Variables

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_TIMEOUT` | 30.0 | Default timeout for all operations |
| `MCP_FUZZER_LOG_LEVEL` | INFO | Default log level |
| `MCP_FUZZER_VERBOSE` | false | Enable verbose logging |
| `MCP_FUZZER_OUTPUT_DIR` | reports | Default output directory |

### Safety Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_SAFETY_ENABLED` | false | Enable safety system by default |
| `MCP_FUZZER_FS_ROOT` | ~/.mcp_fuzzer | Default filesystem root for safety |
| `MCP_FUZZER_AUTO_KILL` | true | Auto-kill hanging processes |
| `MCP_FUZZER_RETRY_WITH_SAFETY` | false | Retry with safety on interrupt |

### Runtime Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_MAX_CONCURRENCY` | 5 | Maximum concurrent operations |
| `MCP_FUZZER_RETRY_COUNT` | 1 | Number of retries for failed operations |
| `MCP_FUZZER_RETRY_DELAY` | 1.0 | Delay between retries |

### Transport Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_HTTP_TIMEOUT` | 30.0 | HTTP transport timeout |
| `MCP_FUZZER_SSE_TIMEOUT` | 30.0 | SSE transport timeout |
| `MCP_FUZZER_STDIO_TIMEOUT` | 30.0 | Stdio transport timeout |

### Authentication Environment Variables

| Variable | Description |
|----------|-------------|
| `MCP_API_KEY` | API key for authentication |
| `MCP_HEADER_NAME` | Header name for API key (default: Authorization) |
| `MCP_USERNAME` | Username for basic authentication |
| `MCP_PASSWORD` | Password for basic authentication |
| `MCP_OAUTH_TOKEN` | OAuth token for authentication |

### Watchdog Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_CHECK_INTERVAL` | 1.0 | How often to check processes |
| `MCP_FUZZER_PROCESS_TIMEOUT` | 30.0 | Time before process is considered hanging |
| `MCP_FUZZER_EXTRA_BUFFER` | 5.0 | Extra time before auto-kill |
| `MCP_FUZZER_MAX_HANG_TIME` | 60.0 | Maximum time before force kill |

### Performance Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_PROCESS_MAX_CONCURRENCY` | 5 | Maximum concurrent operations |
| `MCP_FUZZER_PROCESS_RETRY_COUNT` | 1 | Number of retries for failed operations |
| `MCP_FUZZER_PROCESS_RETRY_DELAY` | 1.0 | Delay between retries |

## Configuration Profiles

### Development Profile

```yaml
# config/dev.yaml
global:
  log_level: DEBUG
  verbose: true

safety:
  enabled: false  # Disable for debugging

watchdog:
  auto_kill: false  # Disable for debugging
  check_interval: 0.5

servers:
  local_dev:
    protocol: stdio
    endpoint: "python dev_server.py"
    runs: 5
    phase: realistic
```

### Production Profile

```yaml
# config/prod.yaml
global:
  log_level: WARNING
  verbose: false
  timeout: 60.0

safety:
  enabled: true
  fs_root: "/opt/mcp_fuzzer/safe"

watchdog:
  auto_kill: true
  process_timeout: 120.0
  max_hang_time: 300.0

servers:
  production_api:
    protocol: http
    endpoint: "https://api.production.com"
    runs: 100
    phase: realistic
    timeout: 120.0
```

### Testing Profile

```yaml
# config/test.yaml
global:
  log_level: INFO
  verbose: true

runtime:
  max_concurrency: 10

servers:
  test_server:
    protocol: http
    endpoint: "http://localhost:8000"
    runs: 50
    phase: aggressive
```

## Using Profiles

```bash
# Use development profile
mcp-fuzzer --mode tools --config config/dev.yaml --server local_dev

# Use production profile
mcp-fuzzer --mode tools --config config/prod.yaml --server production_api

# Use testing profile
mcp-fuzzer --mode tools --config config/test.yaml --server test_server
```

## Performance Configuration

### CLI Arguments for Performance Tuning

The following CLI arguments allow fine-tuning of performance-related parameters:

```bash
# Watchdog configuration
mcp-fuzzer --watchdog-check-interval 0.5 \
           --watchdog-process-timeout 45.0 \
           --watchdog-extra-buffer 10.0 \
           --watchdog-max-hang-time 120.0

# Process management configuration
mcp-fuzzer --process-max-concurrency 10 \
           --process-retry-count 3 \
           --process-retry-delay 2.0
```

### Watchdog CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--watchdog-check-interval` | 1.0 | How often to check processes (seconds) |
| `--watchdog-process-timeout` | 30.0 | Time before process is considered hanging |
| `--watchdog-extra-buffer` | 5.0 | Extra time before auto-kill |
| `--watchdog-max-hang-time` | 60.0 | Maximum time before force kill |

### Process Management CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--process-max-concurrency` | 5 | Maximum concurrent operations |
| `--process-retry-count` | 1 | Number of retries for failed operations |
| `--process-retry-delay` | 1.0 | Delay between retries (seconds) |

## Configuration Validation

### Schema Validation

Configuration files are validated against a schema to ensure correctness:

```bash
# Validate configuration file
mcp-fuzzer --validate-config config.yaml
# Output: "Configuration file is valid"

# Validate with errors
mcp-fuzzer --validate-config invalid-config.yaml
# Output: "Configuration validation failed:
#          - Line 5: 'timeout' must be a number, got 'invalid'
#          - Line 10: 'protocol' must be one of ['http', 'sse', 'stdio', 'streamablehttp']"
```

### Environment Variable Validation

```bash
# Check environment variables
mcp-fuzzer --check-env
# Output: "Environment variables check:
#          ✓ MCP_FUZZER_TIMEOUT=30.0
#          ✗ MCP_FUZZER_LOG_LEVEL=INVALID (must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL)
#          ✓ MCP_FUZZER_SAFETY_ENABLED=true"
```

## Configuration Examples

### Basic HTTP Server Configuration

```yaml
servers:
  basic_http:
    protocol: http
    endpoint: "http://localhost:8000"
    runs: 10
    phase: aggressive
    timeout: 30.0
```

### Stdio Server with Safety

```yaml
servers:
  safe_stdio:
    protocol: stdio
    endpoint: "python server.py"
    runs: 20
    phase: realistic
    safety:
      enabled: true
      fs_root: "/tmp/safe_dir"
    watchdog:
      process_timeout: 60.0
      auto_kill: true
```

### Authenticated API Configuration

```yaml
servers:
  authenticated_api:
    protocol: http
    endpoint: "https://api.example.com"
    runs: 50
    phase: realistic
    auth:
      type: api_key
      api_key: "${API_KEY}"
      header_name: "Authorization"
    timeout: 60.0
```

### Multi-Server Configuration

```yaml
servers:
  local_http:
    protocol: http
    endpoint: "http://localhost:8000"
    runs: 10

  local_stdio:
    protocol: stdio
    endpoint: "python server.py"
    runs: 5
    safety:
      enabled: true

  remote_api:
    protocol: http
    endpoint: "https://api.remote.com"
    runs: 20
    auth:
      type: basic
      username: "${USERNAME}"
      password: "${PASSWORD}"
```

## Advanced Configuration

### Conditional Configuration

```yaml
# Use different configurations based on environment
servers:
  api_server:
    protocol: http
    endpoint: "${API_ENDPOINT}"
    runs: "${RUNS:-10}"
    phase: "${PHASE:-aggressive}"
    timeout: "${TIMEOUT:-30.0}"
```

### Configuration Inheritance

```yaml
# Base configuration
base_server: &base_server
  timeout: 30.0
  phase: realistic
  safety:
    enabled: true

# Inherit from base
servers:
  server1:
    <<: *base_server
    protocol: http
    endpoint: "http://localhost:8000"
    runs: 10

  server2:
    <<: *base_server
    protocol: stdio
    endpoint: "python server.py"
    runs: 5
```

### Dynamic Configuration

```yaml
# Use environment-specific settings
servers:
  dynamic_server:
    protocol: http
    endpoint: "http://${HOST:-localhost}:${PORT:-8000}"
    runs: "${RUNS:-10}"
    phase: "${PHASE:-aggressive}"
    timeout: "${TIMEOUT:-30.0}"
    safety:
      enabled: "${SAFETY_ENABLED:-true}"
      fs_root: "${SAFETY_ROOT:-~/.mcp_fuzzer}"
```

## Configuration Best Practices

### 1. Use Environment Variables for Secrets

```yaml
# Good: Use environment variables for sensitive data
auth:
  api_key: "${API_KEY}"
  password: "${PASSWORD}"

# Bad: Don't hardcode secrets
auth:
  api_key: "sk-1234567890abcdef"
  password: "secret123"
```

### 2. Use Profiles for Different Environments

```bash
# Create separate configuration files for different environments
config/
  dev.yaml
  staging.yaml
  prod.yaml
```

### 3. Validate Configuration Files

```bash
# Always validate configuration files before use
mcp-fuzzer --validate-config config.yaml
```

### 4. Use Descriptive Server Names

```yaml
# Good: Descriptive names
servers:
  local_development_server:
    protocol: stdio
    endpoint: "python dev_server.py"

  production_api_endpoint:
    protocol: http
    endpoint: "https://api.production.com"

# Bad: Unclear names
servers:
  server1:
    protocol: stdio
    endpoint: "python server.py"

  server2:
    protocol: http
    endpoint: "https://api.com"
```

### 5. Document Configuration Options

```yaml
# Add comments to explain configuration
servers:
  # Local development server with safety enabled
  local_dev:
    protocol: stdio
    endpoint: "python dev_server.py"
    runs: 5
    phase: realistic
    safety:
      enabled: true  # Enable safety for local development
      fs_root: "/tmp/dev_safe"  # Use temporary directory
```

### 6. Use Configuration Templates

```yaml
# Template for new server configurations
template_server:
  protocol: http
  endpoint: "http://localhost:8000"
  runs: 10
  phase: aggressive
  timeout: 30.0
  safety:
    enabled: false
  watchdog:
    auto_kill: true
    process_timeout: 30.0
```

This comprehensive configuration guide provides all the information needed to effectively configure MCP Server Fuzzer for different environments and use cases.
