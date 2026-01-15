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
# mode: Fuzzing target
#   - tools: Fuzz tool calls and arguments
#   - protocol: Fuzz protocol message shapes
#   - resources: Run deterministic resource spec checks
#   - prompts: Run deterministic prompt spec checks
#   - all: Run tools + protocol fuzzing with spec checks
mode: tools
phase: aggressive
protocol: http
endpoint: "http://localhost:8000/mcp/"
runs: 10
runs_per_type: 5
# protocol_type: Protocol message schema to fuzz in protocol mode.
# See ProtocolExecutor.PROTOCOL_TYPES in
# mcp_fuzzer/fuzz_engine/executor/protocol_executor.py for the canonical list.
protocol_type: "InitializeRequest"

# Spec guard configuration
# spec_guard: Enable deterministic MCP spec checks for protocol/resources/prompts
# spec_resource_uri: Resource URI used for resources checks (file:// or http(s)://)
# spec_prompt_name: Prompt name used for prompts/completions checks
# spec_prompt_args: JSON object string of prompt arguments
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

## Protocol Type Values

Use `protocol_type` in `mode: protocol` to select a specific MCP message schema
to fuzz (for example, when you want to simulate a single request/notification
shape rather than full protocol behavior). The canonical list lives in
`mcp_fuzzer/fuzz_engine/executor/protocol_executor.py` under
`ProtocolExecutor.PROTOCOL_TYPES`.

Accepted values:

- `InitializeRequest`: Client initialization request.
- `ProgressNotification`: Progress notification message.
- `CancelNotification`: Cancellation notification message.
- `ListResourcesRequest`: List available resources request.
- `ReadResourceRequest`: Read a resource by URI request.
- `SetLevelRequest`: Set server logging level request.
- `GenericJSONRPCRequest`: Arbitrary JSON-RPC method payload.
- `CallToolResult`: Tool call result schema.
- `SamplingMessage`: Sampling message payload.
- `CreateMessageRequest`: Sampling create message request.
- `ListPromptsRequest`: List available prompts request.
- `GetPromptRequest`: Get a prompt by name request.
- `ListRootsRequest`: List roots request.
- `SubscribeRequest`: Subscribe to resource updates request.
- `UnsubscribeRequest`: Unsubscribe from resource updates request.
- `CompleteRequest`: Completion request.
- `ListResourceTemplatesRequest`: List resource templates request.
- `ElicitRequest`: Elicitation request.
- `PingRequest`: Ping request.
- `InitializeResult`: Initialization result schema.
- `ListResourcesResult`: List resources result schema.
- `ListResourceTemplatesResult`: List resource templates result schema.
- `ReadResourceResult`: Read resource result schema.
- `ListPromptsResult`: List prompts result schema.
- `GetPromptResult`: Get prompt result schema.
- `ListToolsResult`: List tools result schema.
- `CompleteResult`: Completion result schema.
- `CreateMessageResult`: Create message result schema.
- `ListRootsResult`: List roots result schema.
- `PingResult`: Ping result schema.
- `ElicitResult`: Elicitation result schema.

## Environment Variables

The following environment variables are currently read at startup:

- `MCP_FUZZER_TIMEOUT`
- `MCP_FUZZER_LOG_LEVEL`
- `MCP_FUZZER_SAFETY_ENABLED`
- `MCP_FUZZER_FS_ROOT`
- `MCP_FUZZER_HTTP_TIMEOUT`
- `MCP_FUZZER_SSE_TIMEOUT`
- `MCP_FUZZER_STDIO_TIMEOUT`

## Migration From Pre-Redesign Configs (<=3d61ee4)

The configuration schema is now flat. Ensure these keys are at the top level:
`mode`, `protocol`, `endpoint`, `runs`, `phase`, `output`, `protocol_type`,
`spec_guard`, `spec_resource_uri`, `spec_prompt_name`, and `spec_prompt_args`.
The legacy `output_dir` key is still accepted but deprecated; prefer
`output.directory`.

Legacy (pre-redesign) configs:

```yaml
# output_dir (legacy)
output_dir: "reports"
```

Current configs:

```yaml
mode: "tools"
protocol: "http"
endpoint: "http://localhost:8000"
runs: 10
phase: "aggressive"
protocol_type: "InitializeRequest"
spec_guard: true
spec_resource_uri: "file:///tmp/resource.txt"
spec_prompt_name: "example_prompt"
spec_prompt_args: '{"query":"probe"}'
output:
  directory: "reports"
```

Authentication-related environment variables are documented in the getting-started guide and are used when `--auth-env` is set.

## Export Formats

The CLI can export standardized reports via:

- `--export-csv` (CSV)
- `--export-xml` (XML)
- `--export-html` (HTML)
- `--export-markdown` (Markdown)

These flags can also be placed directly in config files under their flag names,
for example:

```yaml
export_csv: "reports/results.csv"
export_html: "reports/results.html"
```

Standardized output files are currently emitted as JSON; `output.format` is
accepted for compatibility with legacy tooling.

## Authentication Configuration

Authentication can be configured in two ways:

- `--auth-config`: Path to a JSON file defining providers and tool mappings.
- `--auth-env`: Read authentication settings from environment variables.

Example `--auth-config` JSON:

```json
{
  "providers": {
    "api_key_provider": {
      "type": "api_key",
      "api_key": "secret123",
      "header_name": "Authorization"
    }
  },
  "tool_mapping": {
    "example_tool": "api_key_provider"
  }
}
```

When `--auth-env` is used, set the appropriate variables (such as
`MCP_API_KEY`, `MCP_HEADER_NAME`, `MCP_USERNAME`, `MCP_PASSWORD`) before running
the fuzzer.

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

- Standardized output files are currently emitted as JSON; `output.format` is accepted for compatibility.
