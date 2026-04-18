# Getting Started

This guide provides instructions for installing and configuring MCP Server Fuzzer.

## Installation

### From PyPI (Recommended)

```bash
pip install mcp-fuzzer
```

### Docker (Quick Start)

The container runs as a non-root user (UID 1000). Make sure your output directory is writable.

**Linux (HTTP server on host):**

```bash
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/examples/config:/config:ro \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --runs 10
```

**macOS/Windows (HTTP server on host):**

```bash
docker run --rm -it \
  -v $(pwd)/reports:/output \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/examples/config:/config:ro \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://host.docker.internal:8000 --runs 10
```

If you hit permission errors, ensure the output directory is writable by UID 1000:

```bash
sudo chown -R 1000:1000 reports/
```

### From Source

```bash
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
# If you already cloned without submodules, run:
git submodule update --init --recursive
pip install -e .
```

### Verify Installation

```bash
mcp-fuzzer --help
```

You should see the help output with all available options.

## Quick Start

### 1. Set Up Your MCP Server

First, ensure you have an MCP server running. You can use any of these transport protocols:

- **HTTP**: `http://localhost:8000`

- **SSE**: `http://localhost:8000/sse`

- **Stdio**: `python my_server.py`

- **StreamableHTTP**: `http://localhost:8000/mcp` (use `--protocol streamablehttp`)

### 2. Run Basic Fuzzing

#### Tool Fuzzing (Default Mode)

```bash
# Basic tool fuzzing (all tools)
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# With verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --verbose

# With safety system enabled for a local stdio server
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --runs 5 --enable-safety-system
```

#### Single Tool Fuzzing

```bash
# Fuzz only a specific tool
mcp-fuzzer --mode tools --tool analyze_repository --protocol http --endpoint http://localhost:8000 --runs 20

# Fuzz a specific tool with both phases
mcp-fuzzer --mode tools --tool generate_terraform --phase both --protocol http --endpoint http://localhost:8000 --runs 15
```

#### Protocol Fuzzing

```bash
# Basic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# With verbose output
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5 --verbose
```

Use `--protocol-phase aggressive` when you want malformed protocol payloads.

### 3. View Results

Results are displayed in beautiful, colorized tables showing:

- **Success Rate**: Percentage of successful operations
- **Exception Count**: Number of errors encountered
- **Example Exceptions**: Sample error messages for debugging
- **Overall Statistics**: Summary across all tools/protocols
- **Safety Data**: Blocked operations and risk assessments (when enabled)

### 4. Generate Reports

The MCP Fuzzer automatically generates comprehensive reports for each fuzzing session:

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --output-dir "my_reports"

# Generate comprehensive safety report
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --export-safety-data
```

Each fuzzing session creates `session_id`-based reports:
- **`fuzzing_report_<session_id>.json`** - Complete structured data for analysis
- **`fuzzing_report_<session_id>.txt`** - Human-readable summary for sharing
- **`safety_report_<session_id>.json`** - Detailed safety system data (if enabled)

Standardized JSON outputs are also written under
`reports/sessions/<session_id>/` with timestamped filenames (for example,
`*_fuzzing_results.json`).

## Configuration

MCP Fuzzer can be configured using environment variables, configuration files (YAML), or command-line arguments.

For detailed configuration information, see the [Configuration Guide](../configuration/configuration.md).

### Quick Configuration

Create a config file for quick setup:

```yaml
mode: "tools"
protocol: "http"
endpoint: "http://localhost:8000"
runs: 10
timeout: 30.0
log_level: "INFO"
enable_safety_system: true
fs_root: "~/.mcp_fuzzer"
```

## Fuzzing Modes

Tool fuzzing uses `--phase` (`realistic`, `aggressive`, or `both`). Protocol,
resource, prompt, and stateful fuzzing use `--protocol-phase` (`realistic` or
`aggressive`, default: `realistic`).

### Tool Fuzzing Mode

Tests individual tools with various argument combinations:

```bash
# Basic tool fuzzing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Realistic fuzzing (valid data only)
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint http://localhost:8000

# Aggressive fuzzing (malicious data)
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000

# Two-phase fuzzing (both realistic and aggressive)
mcp-fuzzer --mode tools --phase both --protocol http --endpoint http://localhost:8000
```

### Protocol Fuzzing Mode

Tests MCP protocol types with various message structures:

```bash
# Basic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# Realistic protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase realistic --protocol http --endpoint http://localhost:8000

# Aggressive protocol fuzzing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase aggressive --protocol http --endpoint http://localhost:8000
```

### Resource and Prompt Modes

These modes run spec-guard checks (unless `--spec-guard` is disabled) and then
fuzz the related request types.

```bash
# Resource endpoints
mcp-fuzzer --mode resources --protocol http --endpoint http://localhost:8000 \
  --spec-resource-uri file:///tmp/resource.txt

# Prompt endpoints
mcp-fuzzer --mode prompts --protocol http --endpoint http://localhost:8000 \
  --spec-prompt-name summarize \
  --spec-prompt-args '{"text":"hello"}'
```

### Stateful Sequences (Optional)

```bash
# Run learned protocol sequences after protocol fuzzing
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 \
  --stateful --stateful-runs 3
```

## Authentication

### Using Configuration File

Create `auth_config.json`:

```json
{
  "providers": {
    "openai_api": {
      "type": "api_key",
      "api_key": "sk-your-openai-api-key",
      "header_name": "Authorization"
    },
    "github_api": {
      "type": "api_key",
      "api_key": "ghp-your-github-token",
      "header_name": "Authorization"
    },
    "basic_auth": {
      "type": "basic",
      "username": "user",
      "password": "password"
    }
  },
  "tool_mapping": {
    "openai_chat": "openai_api",
    "github_search": "github_api",
    "secure_tool": "basic_auth"
  }
}
```

Use with fuzzer:

```bash
mcp-fuzzer --mode tools --protocol http --auth-config auth_config.json --endpoint http://localhost:8000
```

### Using Environment Variables

```bash
export MCP_API_KEY="sk-your-api-key"
export MCP_USERNAME="user"
export MCP_PASSWORD="password"

mcp-fuzzer --mode tools --protocol http --auth-env --endpoint http://localhost:8000
```

## Safety System

### Basic Safety Features

```bash
# Enable system command blocking (argument-level safety hooks are already on)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --enable-safety-system

# Set filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --fs-root /tmp/safe_dir

# Disable argument-level safety (not recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --no-safety

```

### Safety System Features

- **System Command Blocking**: Prevents execution of dangerous commands when `--enable-safety-system` is set

- **Filesystem Sandboxing**: Confines file operations to specified directories when `--fs-root` is set

- **Process Management**: Safe subprocess handling with watchdog timeouts

- **Safety Hooks**: Detection helpers available if you implement custom blocking

## Reporting and Output

### Basic Reporting

The MCP Fuzzer automatically generates comprehensive reports for each fuzzing session:

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --output-dir "my_reports"
```

### Enhanced Safety Reporting

```bash
# Show comprehensive safety report
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --export-safety-data

# Combine both features
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --safety-report --export-safety-data
```

### Generated Reports

Each fuzzing session creates:

- **`fuzzing_report_<session_id>.json`** - Complete structured data for analysis
- **`fuzzing_report_<session_id>.txt`** - Human-readable summary for sharing
- **`safety_report_<session_id>.json`** - Detailed safety system data (if enabled)

Standardized JSON outputs are also written under
`reports/sessions/<session_id>/` with timestamped filenames.

### Report Contents

- **Session metadata**: Mode, protocol, endpoint, runs, and timestamps
- **Tool results**: Success rates, exceptions, and safety blocks
- **Protocol results**: Error counts and success rates
- **Safety data**: Blocked operations, risk assessments, and system status
- **Summary statistics**: Overall success rates and execution timing

## Common Use Cases

### Testing Local Development Server

```bash
# Test local HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20

# Test local stdio server with safety
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" --runs 10 --enable-safety-system
```

### Testing Production-Like Environment

```bash
# Test with realistic data only
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint https://api.example.com --runs 15

# Test protocol compliance
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase realistic --protocol http --endpoint https://api.example.com --runs-per-type 8
```

### Security Testing

```bash
# Aggressive fuzzing for security testing
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 25

# Protocol security testing
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol-phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 15
```

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure your MCP server is running
2. **Authentication Errors**: Check your auth configuration
3. **Timeout Errors**: Increase timeout values for slow servers
4. **Permission Denied**: Check filesystem permissions for stdio transport

### Debug Mode

```bash
# Enable debug logging
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --log-level DEBUG

# Verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose
```

### Getting Help

```bash
# Show help
mcp-fuzzer --help

# Show help for specific mode
mcp-fuzzer --mode tools --help
mcp-fuzzer --mode protocol --help
```

## Next Steps

- **[Examples](examples.md)** - Working examples and configurations

- **[Architecture](../architecture/architecture.md)** - Understanding the system design

- **[Reference](../development/reference.md)** - Complete command reference

- **[Safety Guide](../components/safety.md)** - Advanced safety configuration
