# Examples

This page provides working examples and configurations for common use cases with MCP Server Fuzzer.

## 🚀 Basic Examples

### HTTP Transport Examples

#### Basic Tool Fuzzing

```bash
# Fuzz tools on HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

# With verbose output
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --verbose

# With custom timeout
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10 --timeout 60.0
```

#### Protocol Fuzzing

```bash
# Fuzz all protocol types
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 5

# Fuzz specific protocol type
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000

# With verbose output
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 5 --verbose
```

### SSE Transport Examples

#### Tool Fuzzing with SSE

```bash
# Basic SSE tool fuzzing
mcp-fuzzer --mode tools --protocol sse --endpoint http://localhost:8000/sse --runs 15

# With realistic data only
mcp-fuzzer --mode tools --phase realistic --protocol sse --endpoint http://localhost:8000/sse --runs 10

# With aggressive data for security testing
mcp-fuzzer --mode tools --phase aggressive --protocol sse --endpoint http://localhost:8000/sse --runs 20
```

#### Protocol Fuzzing with SSE

```bash
# SSE protocol fuzzing
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8000/sse --runs-per-type 8

# Fuzz specific protocol type with SSE
mcp-fuzzer --mode protocol --protocol-type CreateMessageRequest --protocol sse --endpoint http://localhost:8000/sse
```

### Stdio Transport Examples

#### Local Process Fuzzing

```bash
# Fuzz Python script
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10

# Fuzz Node.js server
mcp-fuzzer --mode tools --protocol stdio --endpoint "node server.js" --runs 10

# Fuzz binary executable
mcp-fuzzer --mode tools --protocol stdio --endpoint "./bin/mcp-server" --runs 10
```

#### Stdio with Safety System

```bash
# Enable safety system for stdio
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --enable-safety-system

# With filesystem sandboxing
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --enable-safety-system --fs-root /tmp/safe_dir

# Retry with safety on interrupt
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --retry-with-safety-on-interrupt
```

## 🔐 Authentication Examples

### API Key Authentication

#### Configuration File Approach

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
    }
  },
  "tool_mappings": {
    "openai_chat": "openai_api",
    "github_search": "github_api"
  }
}
```

Use with fuzzer:

```bash
mcp-fuzzer --mode tools --auth-config auth_config.json --endpoint http://localhost:8000
```

#### Environment Variables Approach

```bash
export MCP_API_KEY="sk-your-api-key"
export MCP_HEADER_NAME="Authorization"

mcp-fuzzer --mode tools --auth-env --endpoint http://localhost:8000
```

### Basic Authentication

```bash
export MCP_USERNAME="user"
export MCP_PASSWORD="password"

mcp-fuzzer --mode tools --auth-env --endpoint http://localhost:8000
```

## 🛡️ Safety System Examples

### Basic Safety Configuration

```bash
# Enable safety system
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --enable-safety-system

# Set custom filesystem root
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --fs-root /tmp/mcp_fuzzer_safe

# Disable argument-level safety (not recommended)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --no-safety
```

### Advanced Safety Configuration

```bash
# Custom safety plugin
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --safety-plugin my_safety_module.SafetyProvider

# Retry with safety on interrupt
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --retry-with-safety-on-interrupt

# Combined safety options
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --enable-safety-system \
  --fs-root /tmp/safe_dir \
  --retry-with-safety-on-interrupt
```

## 📊 Fuzzing Strategy Examples

### Two-Phase Fuzzing

#### Tool Fuzzing with Both Phases

```bash
# Run both realistic and aggressive phases
mcp-fuzzer --mode tools --phase both --protocol http --endpoint http://localhost:8000 --runs 15

# Realistic phase only (valid data)
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint http://localhost:8000 --runs 10

# Aggressive phase only (malicious data)
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 20
```

#### Protocol Fuzzing with Both Phases

```bash
# Two-phase protocol fuzzing
mcp-fuzzer --mode protocol --phase both --protocol http --endpoint http://localhost:8000 --runs-per-type 10

# Realistic protocol testing
mcp-fuzzer --mode protocol --phase realistic --protocol http --endpoint http://localhost:8000 --runs-per-type 8

# Aggressive protocol testing
mcp-fuzzer --mode protocol --phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 15
```

## 🔧 Configuration Examples

### Environment Variables Configuration

```bash
# Core configuration
export MCP_FUZZER_TIMEOUT=60.0
export MCP_FUZZER_LOG_LEVEL=DEBUG
export MCP_FUZZER_SAFETY_ENABLED=true

# Transport-specific configuration
export MCP_FUZZER_HTTP_TIMEOUT=60.0
export MCP_FUZZER_SSE_TIMEOUT=60.0
export MCP_FUZZER_STDIO_TIMEOUT=60.0

# Safety configuration
export MCP_FUZZER_FS_ROOT=~/.mcp_fuzzer
export MCP_FUZZER_ENABLE_SAFETY=true

# Run fuzzer
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000
```

## 🧪 Testing Examples

### Local Development Testing

```bash
# Test local HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --verbose

# Test local stdio server with safety
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --runs 10 --enable-safety-system

# Test both modes on local server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 15
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 8
```

### Production-Like Environment Testing

```bash
# Test with realistic data only
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint https://api.example.com --runs 10

# Test protocol compliance
mcp-fuzzer --mode protocol --phase realistic --protocol http --endpoint https://api.example.com --runs-per-type 5

# Test with authentication
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint https://api.example.com --auth-config auth.json
```

### Security Testing

```bash
# Aggressive fuzzing for security testing
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 25

# Protocol security testing
mcp-fuzzer --mode protocol --phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 15

# Combined security testing
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 20
mcp-fuzzer --mode protocol --phase aggressive --protocol http --endpoint http://localhost:8000 --runs-per-type 10
```

## 📝 Custom Transport Examples

### Creating Custom Transport

To create a custom transport, implement the `TransportProtocol` interface:

```python
from mcp_fuzzer.transport import TransportProtocol

class CustomTransport(TransportProtocol):
    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.config = kwargs

    async def send_request(self, method: str, params=None):
        # Your custom implementation
        return {"result": "custom_response"}
```

### Using Custom Transport

```python
from mcp_fuzzer.client import UnifiedMCPFuzzerClient

# Create custom transport
transport = CustomTransport("custom-endpoint")

# Use with fuzzer client
client = UnifiedMCPFuzzerClient(transport)

# Run fuzzing
await client.fuzz_tools(runs=10)
```

## 🔍 Debugging Examples

### Verbose Output

```bash
# Enable verbose logging
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose

# Set specific log level
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --log-level DEBUG

# Combine verbose and log level
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose --log-level DEBUG
```

### Error Handling

```bash
# Test with increased timeout for slow servers
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --timeout 120.0

# Test with retry mechanism
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --retry-with-safety-on-interrupt

# Test with custom tool timeout
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --tool-timeout 60.0
```

## 📊 Output Examples

### Tool Fuzzer Output

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Tool Fuzzer Results                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Tool Name        │ Success Rate │ Exception Count │ Example Exceptions        │
├─────────────────────────────────────────────────────────────────────────────────┤
│ get_weather      │ 85.0%        │ 3               │ Invalid city name        │
│ search_web       │ 92.0%        │ 1               │ Network timeout          │
│ calculate_math   │ 100.0%       │ 0               │ None                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Overall          │ 92.3%        │ 4               │ 3 tools tested           │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Protocol Fuzzer Output

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Protocol Fuzzer Results                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Protocol Type        │ Total Runs │ Successful │ Exceptions │ Success Rate │
├─────────────────────────────────────────────────────────────────────────────────┤
│ InitializeRequest    │ 5           │ 5          │ 0          │ 100.0%       │
│ ProgressNotification │ 5           │ 4          │ 1          │ 80.0%        │
│ CancelNotification   │ 5           │ 5          │ 0          │ 100.0%       │
├─────────────────────────────────────────────────────────────────────────────────┤
│ Overall              │ 15          │ 14         │ 1          │ 93.3%        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 Performance Examples

### High-Volume Testing

```bash
# High-volume tool fuzzing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 100

# High-volume protocol fuzzing
mcp-fuzzer --mode protocol --protocol http --endpoint http://localhost:8000 --runs-per-type 50

# Concurrent testing with multiple endpoints
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 50 &
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8001 --runs 50 &
wait
```

### Load Testing

```bash
# Load test with realistic data
mcp-fuzzer --mode tools --phase realistic --protocol http --endpoint http://localhost:8000 --runs 200

# Load test with aggressive data
mcp-fuzzer --mode tools --phase aggressive --protocol http --endpoint http://localhost:8000 --runs 200

# Monitor performance
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 100 --log-level INFO
```

These examples cover the most common use cases and should help you get started with MCP Server Fuzzer. For more advanced configurations and customizations, refer to the [Reference](reference.md) and [Architecture](architecture.md) documentation.
