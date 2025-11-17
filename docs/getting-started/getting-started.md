# Getting Started

This guide provides instructions for installing and configuring MCP Server Fuzzer.

## Installation

### From PyPI (Recommended)

```bash
pip install mcp-fuzzer
```

### From Source

```bash
git clone https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
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

- **Stdio**: `python test_server.py`

### 2. Run Basic Fuzzing

#### Tool Fuzzing (Default Mode)

```bash
# Basic tool fuzzing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# With verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --verbose

# With safety system enabled
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 5 --enable-safety-system
```

#### Protocol Fuzzing

```bash
# Basic protocol fuzzing
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# With verbose output
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 5 --verbose
```

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
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --output-dir "my_reports"

# Generate comprehensive safety report
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --export-safety-data
```

Each fuzzing session creates timestamped reports:
- **`fuzzing_report_YYYYMMDD_HHMMSS.json`** - Complete structured data for analysis
- **`fuzzing_report_YYYYMMDD_HHMMSS.txt`** - Human-readable summary for sharing
- **`safety_report_YYYYMMDD_HHMMSS.json`** - Detailed safety system data (if enabled)

## Configuration

MCP Fuzzer can be configured using environment variables, configuration files (YAML or TOML), or command-line arguments.

For detailed configuration information, see the [Configuration Guide](../configuration/configuration.md).

### Quick Configuration

Set these environment variables for quick configuration:

```json
{
  "defaults": {
    "timeout": 30.0,
    "log_level": "INFO",
    "enable_safety_system": true,
    "fs_root": "~/.mcp_fuzzer"
  },
  "servers": {
    "local_http": {
      "protocol": "http",
      "endpoint": "http://localhost:8000",
      "runs": 10
    },
    "local_stdio": {
      "protocol": "stdio",
      "endpoint": "python test_server.py",
      "runs": 5,
      "enable_safety_system": true
    }
  }
}
```

## Fuzzing Modes

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
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# Realistic protocol fuzzing
mcp-fuzzer --mode protocol --phase realistic --protocol http --endpoint http://localhost:8000

# Aggressive protocol fuzzing
mcp-fuzzer --mode protocol --phase aggressive --protocol http --endpoint http://localhost:8000
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
mcp-fuzzer --mode tools --auth-config auth_config.json --endpoint http://localhost:8000
```

### Using Environment Variables

```bash
export MCP_API_KEY="sk-your-api-key"
export MCP_USERNAME="user"
export MCP_PASSWORD="password"

mcp-fuzzer --mode tools --auth-env --endpoint http://localhost:8000
```

## Safety System

### Basic Safety Features

```bash
# Enable system command blocking (argument-level filtering is already on)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --enable-safety-system

# Set filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --fs-root /tmp/safe_dir

# Disable argument-level safety (not recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --no-safety

```

### Safety System Features

- **System Command Blocking**: Prevents execution of dangerous commands

- **Filesystem Sandboxing**: Confines file operations to specified directories

- **Process Isolation**: Safe subprocess handling with timeouts

- **Dangerous Content Filtering**: URL/script/command pattern detection with mock responses

## Reporting and Output

### Basic Reporting

The MCP Fuzzer automatically generates comprehensive reports for each fuzzing session:

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --output-dir "my_reports"
```

### Enhanced Safety Reporting

```bash
# Show comprehensive safety report
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --export-safety-data

# Combine both features
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --safety-report --export-safety-data
```

### Generated Reports

Each fuzzing session creates:

- **`fuzzing_report_YYYYMMDD_HHMMSS.json`** - Complete structured data for analysis
- **`fuzzing_report_YYYYMMDD_HHMMSS.txt`** - Human-readable summary for sharing
- **`safety_report_YYYYMMDD_HHMMSS.json`** - Detailed safety system data (if enabled)

### Report Contents

- **Session metadata**: Configuration, timestamps, and execution parameters
- **Tool results**: Success rates, exceptions, and safety blocks
- **Protocol results**: Error counts and security ratings
- **Safety data**: Blocked operations, risk assessments, and system status
- **Summary statistics**: Overall success rates and performance metrics

## Common Use Cases

### Testing Local Development Server

```bash
# Test local HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20

# Test local stdio server with safety
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --enable-safety-system
```

### Testing Production-Like Environment

```bash
# Test with realistic data only
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint https://api.example.com --runs 15

# Test protocol compliance
mcp-fuzzer --mode protocol --phase realistic --protocol http --endpoint https://api.example.com --runs-per-type 8
```

### Security Testing

```bash
# Aggressive fuzzing for security testing
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 25

# Protocol security testing
mcp-fuzzer --mode protocol --phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 15
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
