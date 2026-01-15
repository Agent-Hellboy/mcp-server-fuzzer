# Configuration Guide

This guide covers how to configure MCP Server Fuzzer using YAML config files, environment variables, and CLI arguments.

## Configuration Methods

MCP Server Fuzzer supports multiple configuration methods in order of precedence:

1. **Command-line arguments** (highest precedence)
2. **Configuration files** (YAML)
3. **Environment variables** (lowest precedence)

Use config files when you want repeatable runs or want to avoid long CLI invocations.

## Configuration Files

### YAML Configuration

Create a `mcp-fuzzer.yaml` or `mcp-fuzzer.yml` file:

```yaml
# Core fuzzing settings
mode: tools
phase: aggressive
protocol: http
endpoint: "http://localhost:8000/mcp/"
runs: 10
runs_per_type: 5
protocol_type: "InitializeRequest"

# Spec guard (protocol/resources/prompts modes)
spec_guard: true
spec_resource_uri: "file:///tmp/resource.txt"
spec_prompt_name: "example_prompt"
spec_prompt_args: '{"name":"value"}'

# Timeouts and logging
timeout: 30.0
tool_timeout: 10.0
log_level: "INFO"

# Safety and filesystem constraints
safety_enabled: true
enable_safety_system: false
fs_root: "~/.mcp_fuzzer"

# Network restrictions
no_network: false
allow_hosts:
  - "localhost"
  - "127.0.0.1"

# Runtime and watchdog settings
max_concurrency: 5
process_max_concurrency: 5
process_retry_count: 1
process_retry_delay: 1.0
watchdog_check_interval: 1.0
watchdog_process_timeout: 30.0
watchdog_extra_buffer: 5.0
watchdog_max_hang_time: 60.0

# Reporting
output_dir: "reports"
output:
  directory: "reports"
  format: "json"
  types:
    - "fuzzing_results"
    - "safety_summary"
  compress: false
```

### Using Configuration Files

```bash
# Use default config discovery
mcp-fuzzer

# Use an explicit config file
mcp-fuzzer --config /path/to/config.yaml
```

## Environment Variables

The following environment variables are currently read at startup:

- `MCP_FUZZER_TIMEOUT`
- `MCP_FUZZER_LOG_LEVEL`
- `MCP_FUZZER_SAFETY_ENABLED`
- `MCP_FUZZER_FS_ROOT`
- `MCP_FUZZER_HTTP_TIMEOUT`
- `MCP_FUZZER_SSE_TIMEOUT`
- `MCP_FUZZER_STDIO_TIMEOUT`

Authentication-related environment variables are documented in the getting-started guide and are used when `--auth-env` is set.

## Custom Transports

Custom transports can be registered via configuration using the `custom_transports` section:

```yaml
custom_transports:
  mytransport:
    module: "my_package.my_transport"
    class: "MyTransport"
    description: "My custom transport"
```

Use the transport by setting `protocol: mytransport` in the same config file.

## Notes

- The CLI supports additional export flags (`--export-csv`, `--export-xml`, `--export-html`, `--export-markdown`) which can also be placed in config files under their flag names.
- Authentication configuration is supplied via `--auth-config` (JSON) or `--auth-env` on the CLI.
- Standardized output files are currently emitted as JSON; `output.format` is accepted for compatibility.
