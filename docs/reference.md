# Reference

This page provides a complete reference for MCP Server Fuzzer, including all command-line options, API documentation, and configuration details.

## \U0001F4CB Command-Line Reference

### Basic Syntax

```bash
mcp-fuzzer [OPTIONS] --mode {tools|protocol} --protocol {http|sse|stdio} --endpoint ENDPOINT
```

### Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--help` | Flag | - | Show help message and exit |
| `--version` | Flag | - | Show version and exit |
| `--verbose` | Flag | False | Enable verbose logging |
| `--log-level` | Choice | INFO | Set log level (CRITICAL, ERROR, WARNING, INFO, DEBUG) |

### Mode Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--mode` | Choice | Yes | Fuzzing mode: `tools` or `protocol` |
| `--protocol` | Choice | Yes | Transport protocol: `http`, `sse`, or `stdio` |
| `--endpoint` | String | Yes | Server endpoint (URL for http/sse, command for stdio) |

### Transport Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--timeout` | Float | 30.0 | Request timeout in seconds |
| `--auth-config` | Path | - | Path to authentication configuration file |
| `--auth-env` | Flag | False | Use authentication from environment variables |

### Fuzzing Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--phase` | Choice | aggressive | Fuzzing phase: `realistic`, `aggressive`, or `both` |
| `--runs` | Integer | 10 | Number of fuzzing runs per tool (tool mode only) |
| `--runs-per-type` | Integer | 5 | Number of runs per protocol type (protocol mode only) |
| `--protocol-type` | String | - | Fuzz only specific protocol type (protocol mode only) |

### Safety Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--enable-safety-system` | Flag | False | Enable system-level safety features |
| `--fs-root` | Path | ~/.mcp_fuzzer | Restrict filesystem operations to specified directory |
| `--safety-plugin` | String | - | Dotted path to custom safety provider |
| `--no-safety` | Flag | False | Disable argument-level safety filtering (not recommended) |
| `--retry-with-safety-on-interrupt` | Flag | False | Retry once with safety system enabled on Ctrl-C |

### Reporting Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output-dir` | Path | reports | Directory to save reports and exports |
| `--safety-report` | Flag | False | Show comprehensive safety report at end of fuzzing |
| `--export-safety-data` | String | - | Export safety data to JSON file (optional filename) |

### Advanced Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--tool-timeout` | Float | 30.0 | Per-tool call timeout in seconds |

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_FUZZER_TIMEOUT` | 30.0 | Default timeout for all operations |
| `MCP_FUZZER_LOG_LEVEL` | INFO | Default log level |
| `MCP_FUZZER_SAFETY_ENABLED` | false | Enable safety system by default |
| `MCP_FUZZER_FS_ROOT` | ~/.mcp_fuzzer | Default filesystem root for safety |
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

## \U0001F4DA API Reference

### Transport Protocol Interface

The core interface for transport protocols:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

class TransportProtocol(ABC):
    """Abstract base class for transport protocols."""

    @abstractmethod
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC request to the server."""
        pass

    @abstractmethod
    async def send_raw(self, payload: Any) -> Any:
        """Send raw payload to the server."""
        pass

    @abstractmethod
    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Send a JSON-RPC notification to the server."""
        pass

    async def get_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools from the server."""
        # Implementation details...

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a specific tool with arguments."""
        # Implementation details...
```

### Fuzzer Client

The main client for orchestrating fuzzing operations:

```python
class UnifiedMCPFuzzerClient:
    """Unified client for MCP fuzzing operations."""

    def __init__(self, transport: TransportProtocol, safety_system: Optional[SafetySystem] = None):
        self.transport = transport
        self.safety_system = safety_system or SafetySystem()

    async def fuzz_tools(self, runs: int = 10, phase: str = "aggressive") -> Dict[str, Any]:
        """Fuzz tools with specified number of runs and phase."""
        # Implementation details...

    async def fuzz_protocol(self, runs_per_type: int = 5, protocol_type: Optional[str] = None, phase: str = "aggressive") -> Dict[str, Any]:
        """Fuzz protocol types with specified parameters."""
        # Implementation details...
```

### Safety System

Core safety system for protecting against dangerous operations:

```python
class SafetySystem:
    """Core safety system for protecting against dangerous operations."""

    def __init__(self, fs_root: Optional[str] = None, enable_system_blocking: bool = True):
        self.fs_root = fs_root or os.path.expanduser("~/.mcp_fuzzer")
        self.enable_system_blocking = enable_system_blocking
        self.system_blocker = SystemBlocker() if enable_system_blocking else None

    def is_safe_environment(self) -> bool:
        """Check if current environment is safe for dangerous operations."""
        # Implementation details...

    def filter_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Filter potentially dangerous arguments."""
        # Implementation details...
```

## Fuzzing Strategies

### Realistic Strategies

Generate realistic, valid data for tool testing:

```python
class RealisticToolStrategy:
    """Generates realistic, valid data for tool testing."""

    def generate_string(self) -> str:
        """Generate realistic string values."""
        return draw(st.text(min_size=1, max_size=100))

    def generate_number(self) -> Union[int, float]:
        """Generate realistic numeric values."""
        return draw(st.one_of(st.integers(), st.floats()))

    def generate_boolean(self) -> bool:
        """Generate boolean values."""
        return draw(st.booleans())
```

### Aggressive Strategies

Generate malicious/malformed data for security testing:

```python
class AggressiveToolStrategy:
    """Generates malicious/malformed data for security testing."""

    def generate_sql_injection(self) -> str:
        """Generate SQL injection attempts."""
        return draw(st.sampled_from([
            "' OR 1=1; --",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]))

    def generate_xss(self) -> str:
        """Generate XSS attack attempts."""
        return draw(st.sampled_from([
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]))
```

## Output Format

### Tool Fuzzer Results

```python
{
    "tools": [
        {
            "name": "tool_name",
            "success_rate": 85.0,
            "total_runs": 10,
            "successful_runs": 8,
            "exception_count": 2,
            "exceptions": [
                "Invalid argument type",
                "Missing required parameter"
            ],
            "average_response_time": 0.15
        }
    ],
    "overall": {
        "total_tools": 3,
        "total_runs": 30,
        "overall_success_rate": 90.0,
        "total_exceptions": 3
    }
}
```

### Protocol Fuzzer Results

```python
{
    "protocol_types": [
        {
            "name": "InitializeRequest",
            "total_runs": 5,
            "successful_runs": 5,
            "exception_count": 0,
            "success_rate": 100.0,
            "exceptions": [],
            "average_response_time": 0.12
        }
    ],
    "overall": {
        "total_protocol_types": 15,
        "total_runs": 75,
        "overall_success_rate": 93.3,
        "total_exceptions": 5
    }
}
```

## Safety System Reference

### Environment Detection

The safety system automatically detects production environments:

```python
def is_safe_test_environment() -> bool:
    """Check if we're in a safe environment for dangerous tests."""
    # Don't run dangerous tests on production systems
    if (os.getenv("CI") or
        os.getenv("PRODUCTION") or
        os.getenv("DANGEROUS_TESTS_DISABLED")):
        return False

    # Don't run on systems with critical processes
    try:
        with open("/proc/1/comm", "r") as f:
            init_process = f.read().strip()
            if init_process in ["systemd", "init"]:
                return False
    except (OSError, IOError):
        pass

    return True
```

### System Command Blocking

```python
class SystemBlocker:
    """Blocks dangerous system commands during fuzzing."""

    def __init__(self):
        self.blocked_commands = {
            "rm", "del", "format", "shutdown", "reboot",
            "kill", "killall", "pkill", "xkill"
        }
        self.blocked_patterns = [
            r"rm\s+-rf",
            r"del\s+/[sq]",
            r"format\s+[a-z]:",
            r"shutdown\s+",
            r"reboot\s+"
        ]

    def is_blocked(self, command: str) -> bool:
        """Check if command should be blocked."""
        # Implementation details...
```

## Performance Tuning

### Timeout Configuration

```bash
# Increase timeouts for slow servers
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --timeout 120.0 --tool-timeout 60.0

# Set different timeouts for different transports
export MCP_FUZZER_HTTP_TIMEOUT=60.0
export MCP_FUZZER_SSE_TIMEOUT=90.0
export MCP_FUZZER_STDIO_TIMEOUT=30.0
```

### Concurrency Settings

```bash
# High-volume testing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 100

# Multiple concurrent instances
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 50 &
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8001 --runs 50 &
wait
```

## Debugging Reference

### Log Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `CRITICAL` | Critical errors only | Production monitoring |
| `ERROR` | Error conditions | Error tracking |
| `WARNING` | Warning messages | Issue identification |
| `INFO` | General information | Normal operation |
| `DEBUG` | Detailed debugging | Development/debugging |

### Verbose Output

```bash
# Enable verbose logging
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose

# Set specific log level
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --log-level DEBUG

# Combine options
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose --log-level DEBUG
```

### Error Handling

```bash
# Handle timeouts gracefully
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --timeout 60.0

# Retry with safety on interrupt
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --retry-with-safety-on-interrupt

# Custom tool timeout
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --tool-timeout 30.0
```

## Configuration Files

### Authentication Configuration

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

This reference covers all the major aspects of MCP Server Fuzzer. For more detailed information about specific components, see the [Architecture](architecture.md) and [Examples](examples.md) documentation.
