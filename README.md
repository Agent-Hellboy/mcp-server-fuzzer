# MCP Server Fuzzer

A comprehensive super aggressive CLI based fuzzing tool for MCP servers using multiple transport protocols, with support for both **tool argument fuzzing** and **protocol type fuzzing**. Features pretty output using [rich](https://github.com/Textualize/rich).

The most important thing I'm aiming to ensure here is:
If your server conforms to the [MCP schema](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema), this tool will be able to fuzz it effectively.

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)

## Features

### Two-Phase Fuzzing Approach

MCP Fuzzer uses a sophisticated **two-phase approach** for comprehensive testing:

#### Phase 1: Realistic Fuzzing
- **Purpose**: Test server behavior with **valid, realistic data**
- **Data Types**: Valid Base64 strings, proper UUIDs, ISO-8601 timestamps, semantic versions
- **Goals**: Verify correct functionality, find logic bugs, test performance with expected inputs
- **Examples**: `{"version": "2024-11-05", "id": "550e8400-e29b-41d4-a716-446655440000"}`

#### Phase 2: Aggressive Fuzzing
- **Purpose**: Test server security and robustness with **malicious/malformed data**
- **Attack Vectors**: SQL injection, XSS, path traversal, buffer overflows, null bytes
- **Goals**: Find security vulnerabilities, crash conditions, input validation failures
- **Examples**: `{"version": "' OR 1=1; --", "id": "<script>alert('xss')</script>"}`

### Core Capabilities
- **Multi-Protocol Support**: HTTP, SSE, and Stdio transports
- **Tool Discovery**: Automatically discovers available tools from MCP servers
- **Intelligent Fuzzing**: Uses Hypothesis + custom strategies for realistic and aggressive data
- **Safety System**: Built-in protection against dangerous operations with configurable safety levels
- **Comprehensive Testing**: Tests both individual tools and protocol-level operations
- **Detailed Reporting**: Rich output with exception tracking and safety summaries

### Safety Features
- **System Command Blocking**: Prevents execution of dangerous system commands
- **Filesystem Sandboxing**: Confines file operations to specified directories
- **Process Isolation**: Safe subprocess handling with timeouts
- **Environment Detection**: Automatically detects production systems and applies safety rules
- **Configurable Safety Levels**: Enable/disable safety features as needed

### Transport Protocols
- **HTTP/HTTPS**: Standard HTTP transport with authentication support
- **Server-Sent Events (SSE)**: Real-time streaming support
- **Stdio**: Command-line interface for local testing

## 🏗️ Architecture

### Core Components
```
mcp_fuzzer/
├── cli/                    # Command-line interface
│   ├── args.py            # Argument parsing and validation
│   ├── main.py            # Main CLI entry point
│   └── runner.py          # CLI execution logic
├── transport/              # Transport layer implementations
│   ├── base.py            # Abstract transport protocol
│   ├── factory.py         # Transport factory
│   ├── http.py            # HTTP/HTTPS transport
│   ├── sse.py             # Server-Sent Events transport
│   └── stdio.py           # Standard I/O transport
├── fuzzer/                 # Fuzzing engine
│   ├── tool_fuzzer.py     # Tool-level fuzzing
│   └── protocol_fuzzer.py # Protocol-level fuzzing
├── strategy/               # Fuzzing strategies
│   ├── realistic/         # Realistic data generation
│   └── aggressive/        # Aggressive attack vectors
├── safety_system/          # Safety and protection
│   ├── safety.py          # Core safety logic
│   └── system_blocker.py  # System command blocking
└── auth/                   # Authentication providers
    ├── providers.py        # Auth provider implementations
    ├── manager.py          # Auth management
    └── loaders.py          # Configuration loading
```

### Safety System Architecture
The safety system provides multiple layers of protection:

1. **Environment Detection**: Automatically detects production systems
2. **Test Isolation**: Dangerous tests are automatically skipped
3. **System Blocking**: Prevents execution of dangerous commands
4. **Filesystem Sandboxing**: Confines file operations
5. **Process Isolation**: Safe subprocess handling with timeouts

### Architecture Flow

```
┌───────────────────┐     ┌────────────────────┐     ┌────────────────┐
│      CLI          │ ───▶│  Unified Client    │────▶│  Transport     │
│  (`mcp_fuzzer/`)  │     │ (`client.py`)      │     │ (HTTP/SSE/WS/  │
│  - args, auth     │     │  - start/stop      │     │   Stdio)       │
└───────────────────┘     │    system blocker  │     └───────┬────────┘
                          │  - tool/protocol    │             │
                          │    orchestration    │             │ JSON-RPC
                          └─────────┬───────────┘             │
                                    │                         ▼
                         ┌───────────▼──────────┐     ┌─────────────────┐
                         │  Safety Filter       │     │   MCP Server     │
                         │ (`safety.py`)        │     │  Under Test      │
                         │ - block/sanitize     │     └─────────────────┘
                         │ - add safety _meta   │
                         └───────────┬──────────┘
                                     │
                         ┌───────────▼──────────┐
                         │ System Command       │
                         │   Blocker            │
                         │ (`system_blocker.py`)│
                         │ - PATH shim + fakes  │
                         │ - log blocked ops    │
                         └──────────────────────┘
```

### Key Benefits

- **Modular Design**: Clear separation between orchestration and data generation
- **Two-Phase Approach**: Realistic validation testing + aggressive security testing
- **Transport Agnostic**: Fuzzer logic independent of communication protocol
- **Extensible**: Easy to add new transport protocols and fuzzing strategies
- **Phase-Aware**: Strategy selection based on testing goals (realistic vs aggressive)
- **Testable**: Each component can be tested independently

See architecture diagrams in the docs folder

## 📦 Installation

### From PyPI
```bash
pip install mcp-fuzzer
```

### From Source
```bash
git clone https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
pip install -e .
```

## 🚀 Quick Start

### Basic Usage
```bash
# Fuzz tools on an HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# Fuzz protocol types on an SSE server
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8000/sse --runs-per-type 5

# Fuzz with safety system enabled
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 5 --enable-safety-system
```

### Common Arguments
- `--mode`: Fuzzing mode (`tools` or `protocol`, default: `tools`)
- `--protocol`: Transport protocol to use (http, sse, stdio)
- `--endpoint`: Server endpoint (URL for http/sse, command for stdio)
- `--timeout`: Request timeout in seconds (default: 30.0)
- `--verbose`: Enable verbose logging
- `--runs`: Number of fuzzing runs per tool (default: 3)
- `--runs-per-type`: Number of runs per protocol type (default: 3)
- `--enable-safety-system`: Enable system-level safety features
- `--fs-root`: Restrict filesystem operations to specified directory
- `--tool-timeout`: Timeout for individual tool calls (default: 30.0)

### Tool Fuzzing

```bash
# Basic tool fuzzing (aggressive by default)
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ --runs 10

# Realistic tool fuzzing - test with valid arguments
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint http://localhost:8000/mcp/

# Two-phase tool fuzzing
mcp-fuzzer --mode tools --phase both --protocol http --endpoint http://localhost:8000/mcp/
```

### Protocol Fuzzing

```bash
# Basic protocol fuzzing (aggressive by default)
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 5

# Realistic protocol fuzzing - test with valid MCP messages
mcp-fuzzer --mode protocol --phase realistic --protocol http --endpoint http://localhost:8000/mcp/

# Two-phase protocol fuzzing
mcp-fuzzer --mode protocol --phase both --protocol http --endpoint http://localhost:8000/mcp/

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000/mcp/

# Fuzz with verbose output
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000/mcp/ --verbose
```

### Authentication Support

The fuzzer supports authentication for tools that require it:

```bash
# Using authentication configuration file
mcp-fuzzer --mode tools --auth-config examples/auth_config.json --endpoint http://localhost:8000

# Using environment variables
mcp-fuzzer --mode tools --auth-env --endpoint http://localhost:8000
```

#### Authentication Configuration

Create a JSON configuration file (`auth_config.json`):

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
  "tool_mappings": {
    "openai_chat": "openai_api",
    "github_search": "github_api",
    "secure_tool": "basic_auth"
  }
}
```

#### Environment Variables

Set authentication via environment variables:

```bash
export MCP_API_KEY="sk-your-api-key"
export MCP_USERNAME="user"
export MCP_PASSWORD="password"
export MCP_OAUTH_TOKEN="your-oauth-token"

mcp-fuzzer --mode tools --auth-env --endpoint http://localhost:8000
```

#### Supported Authentication Types

- **API Key**: Bearer token authentication
- **Basic Auth**: Username/password authentication
- **OAuth Token**: OAuth token authentication
- **Custom Headers**: Custom authentication headers

## Supported Protocol Types

The protocol fuzzer covers all major MCP protocol types:

### Core Protocol
- **InitializeRequest**: Tests protocol version handling, client info, and capabilities
- **ProgressNotification**: Tests progress tokens, negative progress, and malformed notifications
- **CancelNotification**: Tests cancellation of unknown/completed requests

### Resource Management
- **ListResourcesRequest**: Tests pagination cursors and edge cases
- **ReadResourceRequest**: Tests URI parsing, path traversal, and malformed URIs
- **SubscribeRequest**: Tests resource subscription with invalid URIs
- **UnsubscribeRequest**: Tests resource unsubscription edge cases

### Logging & Configuration
- **SetLevelRequest**: Tests invalid logging levels and boundary conditions

### LLM & Sampling
- **CreateMessageRequest**: Tests large prompts, invalid tokens, and malformed messages
- **SamplingMessage**: Tests message content and role validation

### Prompt Management
- **ListPromptsRequest**: Tests prompt listing pagination
- **GetPromptRequest**: Tests prompt retrieval with invalid names

### Root Management
- **ListRootsRequest**: Tests root listing functionality

### Completion
- **CompleteRequest**: Tests completion with invalid references and arguments

### Generic JSON-RPC
- **GenericJSONRPCRequest**: Tests malformed JSON-RPC messages, missing fields, and invalid versions

## Custom Transport Protocols

The MCP Fuzzer uses a transport abstraction layer that makes it easy to implement custom transport protocols. You can create your own transport by inheriting from `TransportProtocol`:

### Creating Custom Transports

```python
from mcp_fuzzer.transport import TransportProtocol

class YourCustomTransport(TransportProtocol):
    def __init__(self, your_config):
        # Your initialization
        pass

    async def send_request(self, method: str, params=None) -> Any:
        # Your custom implementation
        return your_response
```

### Example Custom Transports

The project includes examples of custom transport implementations:

- **gRPC Transport**: High-performance RPC communication
- **Redis Transport**: Pub/sub messaging via Redis
- **Webhook Transport**: HTTP webhook-based communication

See `examples/custom_transport_example.py` for complete implementation examples.

### Integration Options

**Option 1: Extend the factory function**
```python
def create_custom_transport(protocol, endpoint, **kwargs):
    if protocol == "your-protocol":
        return YourCustomTransport(endpoint, **kwargs)
    else:
        return create_transport(protocol, endpoint, **kwargs)
```

**Option 2: Direct usage**
```python
from your_module import YourCustomTransport

transport = YourCustomTransport("your-endpoint")
client = UnifiedMCPFuzzerClient(transport)
```

### Benefits of Custom Transports

- **Plug-and-play**: Just implement the interface
- **Zero fuzzer changes**: Fuzzer doesn't know about transport
- **Protocol agnostic**: Works with any transport
- **Easy testing**: Mock transports for testing

## Supported Protocols
```bash
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8080/rpc --runs 20
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8080/rpc --runs-per-type 10
```

### SSE Transport
```bash
mcp-fuzzer --mode tools --protocol sse --endpoint http://localhost:8080/sse --runs 15
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8080/sse --runs-per-type 8
```

### Stdio Transport
```bash
# Binary executables
mcp-fuzzer --mode tools --protocol stdio --endpoint "./bin/mcp-shell" --runs 10
mcp-fuzzer --mode protocol --protocol stdio --endpoint "./bin/mcp-shell" --runs-per-type 5

# Python scripts
mcp-fuzzer --mode tools --protocol stdio --endpoint "python3 ./my-mcp-server.py" --runs 10
mcp-fuzzer --mode protocol --protocol stdio --endpoint "python3 ./my-mcp-server.py" --runs-per-type 5

# With safety system enabled (blocks external app launches)
mcp-fuzzer --mode tools --protocol stdio --enable-safety-system \
  --endpoint "python3 ./my-mcp-server.py" --runs 10

# Control logging verbosity
mcp-fuzzer --mode tools --protocol stdio --endpoint "python3 ./my-mcp-server.py" \
  --runs 10 --log-level INFO

# Retry once with safety on Ctrl-C (helpful if a tool run hangs)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python3 ./my-mcp-server.py" \
  --runs 10 --retry-with-safety-on-interrupt
```

## Arguments

### Common Arguments
- `--mode`: Fuzzing mode (`tools` or `protocol`, default: `tools`)
- `--protocol`: Transport protocol to use (http, sse, stdio)
- `--endpoint`: Server endpoint (URL for http/sse, command for stdio)
- `--timeout`: Request timeout in seconds (default: 30.0)
- `--verbose`: Enable verbose logging
- `--log-level`: Explicit log level override (`CRITICAL|ERROR|WARNING|INFO|DEBUG`). Overrides `--verbose` when provided.
- `--phase`: realistic | aggressive | both (controls data generation phase)
- `--fs-root`: sandbox directory for any file operations originating from tool calls (default: `~/.mcp_fuzzer`)
- `--enable-safety-system`: enable PATH shim to block external commands during fuzzing
- `--safety-plugin`: dotted path for a custom safety provider (must expose `get_safety()` or `safety` object)
- `--no-safety`: disable argument-level safety filtering (not recommended)
- `--retry-with-safety-on-interrupt`: on Ctrl-C, retry once with safety system enabled if it wasn’t already
- `--tool-timeout`: per-tool call timeout in seconds (overrides `--timeout` for each tool invocation)

### Tool Fuzzer Arguments
- `--runs`: Number of fuzzing runs per tool (default: 10)

### Protocol Fuzzer Arguments
- `--runs-per-type`: Number of fuzzing runs per protocol type (default: 5)
- `--protocol-type`: Fuzz only a specific protocol type (optional)

## Output

Results are shown in colorized tables with detailed statistics:

### Tool Fuzzer Output
- **Success Rate**: Percentage of successful tool calls
- **Exception Count**: Number of exceptions during fuzzing
- **Example Exceptions**: Sample error messages for debugging
- **Overall Statistics**: Summary across all tools and protocols

### Protocol Fuzzer Output
- **Protocol Type**: The specific MCP protocol type being tested
- **Total Runs**: Number of fuzz attempts for this protocol type
- **Successful**: Number of successful protocol interactions
- **Exceptions**: Number of exceptions or errors encountered
- **Success Rate**: Percentage of successful protocol interactions
- **Example Exception**: Sample error messages for debugging

## Edge Cases Tested

The protocol fuzzer generates comprehensive edge cases including:

### InitializeRequest
- Invalid protocol versions
- Malformed client info
- Invalid capabilities structures
- Empty or missing fields

### ProgressNotification
- Negative progress values
- Invalid progress tokens
- Missing required fields
- Malformed progress structures

### ReadResourceRequest
- Path traversal attempts (`../../../etc/passwd`)
- Invalid URI schemes
- Extremely long URIs
- Unicode and special characters in paths
- Data URIs with malformed content

### SetLevelRequest
- Invalid logging levels
- Numeric and boolean values instead of strings
- Empty or malformed level strings
- Boundary testing of log systems

### Generic JSON-RPC
- Missing `jsonrpc` field
- Invalid JSON-RPC versions
- Missing request IDs
- Deeply nested parameters
- Malformed JSON-RPC structures

### Examples

#### HTTP Transport
```bash
# Fuzz tools on HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 25

# Fuzz protocol types on HTTP server
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 12

# With authentication
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --auth-config auth.json
```

#### SSE Transport
```bash
# Fuzz tools on SSE server
mcp-fuzzer --mode tools --protocol sse --endpoint http://localhost:8000/sse --runs 25

# Fuzz protocol types on SSE server
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8000/sse --runs-per-type 12
```

#### Stdio Transport
```bash
# Fuzz tools on local stdio server
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10

# With safety system enabled
mcp-fuzzer --mode tools --protocol stdio --endpoint "node server.js" --runs 5 --enable-safety-system

# With filesystem sandboxing
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --runs 10 --fs-root /tmp/safe_dir
```

## Testing

### Running Tests
```bash
# Run all tests
pytest

# Run specific test modules
pytest tests/test_transport.py
pytest tests/test_cli.py

# Run with coverage
pytest --cov=mcp_fuzzer

# Run with verbose output
pytest -v -s
```

### Test Safety Features
The test suite includes built-in safety measures:
- **Environment Detection**: Automatically detects production systems
- **Dangerous Test Skipping**: Subprocess and system-level tests are automatically skipped on production
- **Safe Mocking**: All tests use proper mocking without real system calls
- **Isolation**: Tests are isolated and won't affect system stability

### Test Coverage
- **Transport Layer**: HTTP, SSE, and Stdio transport implementations
- **CLI Interface**: Command-line argument parsing and execution
- **Safety System**: Safety features and protection mechanisms
- **Fuzzing Engine**: Tool and protocol fuzzing logic
- **Authentication**: Various authentication provider implementations

## Development

### Project Structure
The project follows a modular architecture with clear separation of concerns:
- **`cli/`**: Command-line interface and argument handling
- **`transport/`**: Transport protocol implementations
- **`fuzzer/`**: Core fuzzing engine
- **`strategy/`**: Data generation strategies
- **`safety_system/`**: Safety and protection mechanisms
- **`auth/`**: Authentication provider implementations

### Adding New Features
1. **New Transport Protocols**: Implement `TransportProtocol` interface
2. **New Fuzzing Strategies**: Add strategies to `strategy/` directory
3. **New Safety Features**: Extend `safety_system/` modules
4. **New Authentication**: Implement auth provider interface

### Code Quality
- **Linting**: Uses `ruff` for code quality checks
- **Testing**: Comprehensive test suite with safety measures
- **Type Hints**: Full type annotation support
- **Documentation**: Inline documentation and examples

## Documentation

- **Architecture**: See `docs/mermaid_architecture.md` for detailed diagrams
- **API Reference**: Inline documentation in source code
- **Examples**: Working examples in `examples/` directory
- **Safety Guide**: Safety system configuration and usage

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper tests
4. Ensure all tests pass and safety measures work
5. Submit a pull request

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Disclaimer

This tool is designed for testing and security research. Always use in controlled environments and ensure you have permission to test the target systems. The safety system provides protection but should not be relied upon as the sole security measure.
