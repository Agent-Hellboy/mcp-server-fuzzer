# MCP Fuzzer

A comprehensive super aggressive CLI based fuzzing tool for MCP servers using multiple transport protocols, with support for both **tool argument fuzzing** and **protocol type fuzzing**. Features pretty output using [rich](https://github.com/Textualize/rich).

The most important thing I'm aiming to ensure here is:
If your server conforms to the [2024-11-05 MCP schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2024-11-05/schema.ts), this tool will be able to fuzz it effectively.

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
- **Multi-Protocol Support**: HTTP, SSE, Stdio, and WebSocket transports
- **Tool Discovery**: Automatically discovers available tools from MCP servers
- **Intelligent Fuzzing**: Uses Hypothesis + custom strategies for realistic and aggressive data
- **Authentication Support**: Handle API keys, OAuth tokens, basic auth, and custom headers
- **Rich Reporting**: Beautiful terminal tables with separate phase statistics
- **Protocol Flexibility**: Easy to add new transport protocols
- **Comprehensive Protocol Coverage**: Fuzzes all MCP protocol types in both phases
- **Edge Case Generation**: Tests malformed requests, invalid parameters, and boundary conditions
- **Protocol-Specific Strategies**: Tailored fuzzing for each MCP message type
- **State-Aware Testing**: Tests protocol flow and state transitions
- **Security Testing**: Path traversal, injection attacks, and malformed data
- **Safety System (Guaranteed No External Launches)**: Argument-level sanitization blocks URLs and dangerous commands; system-level command blocking prevents opening browsers or launching apps during fuzzing; results include safety metadata and a post-run summary of blocked operations


## Architecture

The MCP Fuzzer uses a modular architecture with clear separation of concerns:

### Core Components

- **`client.py`**: Unified client that orchestrates both tool and protocol fuzzing
- **`transport.py`**: Abstract transport layer supporting HTTP, SSE, Stdio, WebSocket, and custom protocols
- **`fuzzer/`**: Orchestration logic for different fuzzing types
  - `tool_fuzzer.py`: Tool argument fuzzing orchestration
  - `protocol_fuzzer.py`: Protocol type fuzzing orchestration
- **`strategy/`**: Two-phase Hypothesis-based data generation strategies
  - `strategy_manager.py`: Main interface providing `ProtocolStrategies` and `ToolStrategies`
  - `realistic/`: Realistic data generation (valid inputs)
    - `tool_strategy.py`: Realistic tool argument strategies (Base64, UUID, timestamps)
    - `protocol_type_strategy.py`: Realistic protocol message strategies
  - `aggressive/`: Aggressive data generation (malicious/malformed inputs)
    - `tool_strategy.py`: Aggressive tool argument strategies (injections, overflows)
    - `protocol_type_strategy.py`: Aggressive protocol message strategies

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

## Installation

```bash
pip install mcp-fuzzer
```

## Usage

### Two-Phase Fuzzing

Choose your fuzzing approach based on what you want to test:

```bash
# Realistic Phase - Test with valid data (should work)
mcp-fuzzer --mode both --phase realistic --protocol http --endpoint http://localhost:8000/mcp/

# Aggressive Phase - Test with attack data (should be rejected)
mcp-fuzzer --mode both --phase aggressive --protocol http --endpoint http://localhost:8000/mcp/

# Two-Phase - Run both phases for comprehensive testing
mcp-fuzzer --mode both --phase both --protocol http --endpoint http://localhost:8000/mcp/
```

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
```

### WebSocket Transport
```bash
mcp-fuzzer --mode tools --protocol websocket --endpoint ws://localhost:8080/ws --runs 25
mcp-fuzzer --mode protocol --protocol websocket --endpoint ws://localhost:8080/ws --runs-per-type 12
```

## Arguments

### Common Arguments
- `--mode`: Fuzzing mode (`tools` or `protocol`, default: `tools`)
- `--protocol`: Transport protocol to use (http, sse, stdio, websocket)
- `--endpoint`: Server endpoint (URL for http/sse/websocket, command for stdio)
- `--timeout`: Request timeout in seconds (default: 30.0)
- `--verbose`: Enable verbose logging

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

## Examples

### Testing a Simple MCP Server

```bash
# Start your MCP server
python my-mcp-server.py

# In another terminal, fuzz the tools
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ --runs 20

# Fuzz the protocol types
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 10
```

### Testing Specific Protocol Vulnerabilities

```bash
# Test initialization edge cases
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 20

# Test resource reading with path traversal
mcp-fuzzer --mode protocol --protocol-type ReadResourceRequest --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 15

# Test logging level boundary conditions
mcp-fuzzer --mode protocol --protocol-type SetLevelRequest --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 10
```

## Development

### Running Tests

```bash
# Test the protocol fuzzer
python examples/test_protocol_fuzzer.py

# Test custom transport examples
python examples/custom_transport_example.py

# Run the full test suite
python -m pytest tests/
```

### Adding New Protocol Types

To add fuzzing for a new MCP protocol type:

1. Add realistic strategy in `strategy/realistic/protocol_type_strategy.py`
2. Add aggressive strategy in `strategy/aggressive/protocol_type_strategy.py`
3. Add the protocol type to the mapping in `strategy/aggressive/protocol_type_strategy.py:get_protocol_fuzzer_method()`
4. Add the send method in `client.py` (in the `_send_protocol_request` method)
5. Update the protocol types list in `ProtocolFuzzer.fuzz_all_protocol_types()`

### Adding New Transport Protocols

To add a new transport protocol:

1. Create a new class inheriting from `TransportProtocol` in `transport.py`
2. Implement the `send_request()` method
3. Add the protocol to the `create_transport()` factory function
4. Update the CLI argument parser in `__main__.py` if needed

---

**Project dependencies are managed via `pyproject.toml`.**

Example response from a server using examples/test_server.py → **Warning**: If schema validation is not implemented in your server, it may be vulnerable to crashes or unexpected behavior when receiving malformed requests.

![fuzz_resp](./images/fuzz_resp.png)
