# Reference

This page provides a complete reference for MCP Server Fuzzer, including all command-line options, API documentation, and configuration details.

## Command-Line Reference

### Basic Syntax

```bash
mcp-fuzzer [OPTIONS] --mode {tools|protocol|both} --protocol {http|sse|stdio|streamablehttp} --endpoint ENDPOINT
```

### Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--help` | Flag | - | Show help message and exit |
| `--version` | Flag | - | Show version and exit |
| `--verbose` | Flag | False | Enable verbose logging |
| `--log-level` | Choice | WARNING (INFO with `--verbose`) | Set log level (CRITICAL, ERROR, WARNING, INFO, DEBUG). Defaults to WARNING, or INFO when `--verbose` is set |

### Mode Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--mode` | Choice | Yes | Fuzzing mode: `tools`, `protocol`, or `both` |
| `--protocol` | Choice | Yes | Transport protocol: `http`, `sse`, `stdio`, or `streamablehttp` |
| `--endpoint` | String | Yes | Server endpoint (URL for http/sse, command for stdio) |

### Transport Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--timeout` | Float | 30.0 | Request timeout in seconds |
| `--auth-config` | Path | - | Path to authentication configuration file |
| `--auth-env` | Flag | False | Use authentication from environment variables |

Notes:

- When using `--protocol streamablehttp` the client:

  - Performs an automatic MCP initialize handshake before the first request.
  - Propagates `mcp-session-id` and `mcp-protocol-version` headers after negotiation.
  - Follows 307/308 redirects (e.g., adds a trailing slash `/mcp/`).

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

## Runtime Management API Reference

The runtime management system provides robust, asynchronous subprocess lifecycle management for transports and target servers under test.

### ProcessManager

The `ProcessManager` provides fully asynchronous subprocess lifecycle management with comprehensive process tracking and signal handling.

#### Class Definition

```python
class ProcessManager:
    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the async process manager."""
```

#### Configuration

```python
@dataclass
class ProcessConfig:
    command: List[str]                    # Command and arguments to execute
    cwd: Optional[Union[str, Path]] = None  # Working directory
    env: Optional[Dict[str, str]] = None     # Environment variables
    timeout: float = 30.0                    # Default timeout for operations
    auto_kill: bool = True                  # Whether to auto-kill hanging processes
    name: str = "unknown"                   # Human-readable name for logging
    activity_callback: Optional[Callable[[], float]] = None  # Activity callback
```

#### Methods

- `async start_process(config: ProcessConfig) -> asyncio.subprocess.Process`
  - Start a new process asynchronously
  - Returns the created subprocess object
  - Automatically registers process with watchdog

- `async stop_process(pid: int, force: bool = False) -> bool`
  - Stop a running process gracefully or forcefully
  - Returns True if process was stopped successfully
  - Uses SIGTERM for graceful, SIGKILL for force

- `async stop_all_processes(force: bool = False) -> None`
  - Stop all running processes
  - Can be graceful or forceful
  - Executes concurrently for all processes

- `async get_process_status(pid: int) -> Optional[Dict[str, Any]]`
  - Get detailed status information for a specific process
  - Returns None if process is not managed
  - Includes start time, status, and configuration

- `async list_processes() -> List[Dict[str, Any]]`
  - Get list of all managed processes with their status
  - Returns comprehensive process information

- `async wait_for_process(pid: int, timeout: Optional[float] = None) -> Optional[int]`
  - Wait for a process to complete
  - Returns exit code or None if timeout
  - Non-blocking with configurable timeout

- `async update_activity(pid: int) -> None`
  - Update activity timestamp for a process
  - Used for hang detection by watchdog

- `async get_stats() -> Dict[str, Any]`
  - Get overall statistics about managed processes
  - Includes process counts by status and watchdog stats

- `async cleanup_finished_processes() -> int`
  - Remove finished processes from tracking
  - Returns count of cleaned processes
  - Prevents resource leaks

- `async shutdown() -> None`
  - Shutdown the process manager and stop all processes
  - Ensures proper cleanup of all resources

- `async send_timeout_signal(pid: int, signal_type: str = "timeout") -> bool`
  - Send a timeout signal to a running process
  - Signal types: "timeout", "force", "interrupt"
  - Returns True if signal was sent successfully

- `async register_existing_process(pid: int, process: asyncio.subprocess.Process, name: str, activity_callback: Optional[Callable[[], float]] = None) -> None`
  - Register an already-started subprocess with the manager
  - Useful for integrating with existing process management

#### Usage Examples

```python
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig

async def process_manager_example():
    manager = ProcessManager()

    # Start a process
    config = ProcessConfig(
        command=["python", "test_server.py"],
        name="test_server",
        timeout=60.0
    )
    process = await manager.start_process(config)

    # Monitor process
    status = await manager.get_process_status(process.pid)
    print(f"Process {process.pid} status: {status['status']}")

    # Update activity
    await manager.update_activity(process.pid)

    # Get statistics
    stats = await manager.get_stats()
    print(f"Managing {stats['total_managed']} processes")

    # Stop process
    await manager.stop_process(process.pid)

    # Cleanup
    await manager.shutdown()
```

### ProcessWatchdog

The `ProcessWatchdog` provides automated monitoring and termination of hanging processes with configurable thresholds and activity tracking.

#### Class Definition

```python
class ProcessWatchdog:
    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the process watchdog."""
```

#### Configuration

```python
@dataclass
class WatchdogConfig:
    check_interval: float = 1.0      # How often to check processes (seconds)
    process_timeout: float = 30.0    # Time before process is considered hanging (seconds)
    extra_buffer: float = 5.0        # Extra time before auto-kill (seconds)
    max_hang_time: float = 60.0      # Maximum time before force kill (seconds)
    auto_kill: bool = True          # Whether to automatically kill hanging processes
```

#### Methods

- `async start() -> None`
  - Start the watchdog monitoring loop
  - Creates background task for process monitoring

- `async stop() -> None`
  - Stop the watchdog monitoring loop
  - Cancels monitoring task and cleans up

- `async register_process(pid: int, process: Any, activity_callback: Optional[Callable[[], float]], name: str) -> None`
  - Register a process for monitoring
  - Activity callback should return timestamp of last activity
  - Auto-starts watchdog if not already running

- `async unregister_process(pid: int) -> None`
  - Unregister a process from monitoring
  - Removes process from monitoring loop

- `async update_activity(pid: int) -> None`
  - Update activity timestamp for a process
  - Used to indicate process is still active

- `async is_process_registered(pid: int) -> bool`
  - Check if a process is registered for monitoring
  - Returns True if process is being monitored

- `async get_stats() -> dict`
  - Get statistics about monitored processes
  - Includes total, running, and finished process counts

#### Context Manager Support

```python
async with ProcessWatchdog(config) as watchdog:
    # Watchdog automatically starts and stops
    await watchdog.register_process(pid, process, callback, name)
    # ... use watchdog
```

#### Usage Examples

```python
from mcp_fuzzer.fuzz_engine.runtime.watchdog import ProcessWatchdog, WatchdogConfig

async def watchdog_example():
    config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=30.0,
        auto_kill=True
    )

    watchdog = ProcessWatchdog(config)
    await watchdog.start()

    # Register a process
    process = await asyncio.create_subprocess_exec("python", "server.py")
    await watchdog.register_process(
        process.pid,
        process,
        None,  # No activity callback
        "server"
    )

    # Update activity periodically
    for _ in range(10):
        await watchdog.update_activity(process.pid)
        await asyncio.sleep(5)

    # Get statistics
    stats = await watchdog.get_stats()
    print(f"Monitoring {stats['total_processes']} processes")

    await watchdog.stop()
```

### AsyncFuzzExecutor

The `AsyncFuzzExecutor` provides controlled concurrency and robust error handling for fuzzing operations with configurable timeouts and retry mechanisms.

#### Class Definition

```python
class AsyncFuzzExecutor:
    def __init__(
        self,
        max_concurrency: int = 5,      # Maximum concurrent operations
        timeout: float = 30.0,         # Default timeout for operations
        retry_count: int = 1,          # Number of retries for failed operations
        retry_delay: float = 1.0,      # Delay between retries
    ):
```

#### Methods

- `async execute(operation: Callable[..., Awaitable[Any]], *args, timeout: Optional[float] = None, **kwargs) -> Any`
  - Execute a single operation with timeout and error handling
  - Returns result of the operation
  - Respects concurrency limits via semaphore

- `async execute_with_retry(operation: Callable[..., Awaitable[Any]], *args, retry_count: Optional[int] = None, retry_delay: Optional[float] = None, **kwargs) -> Any`
  - Execute an operation with retries on failure
  - Uses exponential backoff for retry delays
  - Does not retry on CancelledError

- `async execute_batch(operations: List[Tuple[Callable[..., Awaitable[Any]], List, Dict]], collect_results: bool = True, collect_errors: bool = True) -> Dict[str, List]`
  - Execute a batch of operations concurrently with bounded concurrency
  - Returns dictionary with 'results' and 'errors' lists
  - Operations are tuples of (callable, args, kwargs)

- `async shutdown(timeout: float = 5.0) -> None`
  - Shutdown the executor, waiting for running tasks to complete
  - Cancels outstanding tasks if timeout is exceeded
  - Ensures proper cleanup of task tracking

#### Usage Examples

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def executor_example():
    executor = AsyncFuzzExecutor(
        max_concurrency=3,
        timeout=10.0,
        retry_count=2
    )

    # Single operation
    async def sample_operation():
        await asyncio.sleep(1)
        return "success"

    result = await executor.execute(sample_operation)

    # Operation with retry
    async def unreliable_operation():
        if random.random() < 0.5:
            raise Exception("Random failure")
        return "success"

    result = await executor.execute_with_retry(unreliable_operation)

    # Batch operations
    operations = [
        (sample_operation, [], {}),
        (unreliable_operation, [], {}),
        (sample_operation, [], {})
    ]

    results = await executor.execute_batch(operations)
    print(f"Results: {len(results['results'])}, Errors: {len(results['errors'])}")

    await executor.shutdown()
```

## CLI Improvements

The MCP Server Fuzzer CLI has been enhanced with better user experience features:

### Progress Indicators

The CLI now provides clear progress indicators during fuzzing operations:

```bash
# Progress indicators show current status
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 100
# Output: [████████████████████████████████████████] 100% Complete
```

### Enhanced Error Messages

Error messages now include suggested fixes and context:

```bash
# Before: "Connection failed"
# After: "Connection failed: Unable to connect to http://localhost:8000
#         Suggested fixes:
#         - Check if the server is running
#         - Verify the endpoint URL is correct
#         - Check firewall settings"
```

### Interactive Help

The CLI provides interactive help for complex configurations:

```bash
# Show help for specific mode
mcp-fuzzer --mode tools --help

# Show help for specific protocol
mcp-fuzzer --protocol stdio --help

# Interactive configuration wizard
mcp-fuzzer --interactive-config
```

### Argument Validation

The CLI now validates argument combinations and provides helpful error messages:

```bash
# Invalid combination detection
mcp-fuzzer --mode protocol --runs 10
# Error: --runs is only valid for tool mode. Use --runs-per-type for protocol mode.

# Missing required arguments
mcp-fuzzer --mode tools
# Error: --protocol and --endpoint are required for tool mode.
```

### Verbose Output Improvements

Enhanced verbose output provides more detailed information:

```bash
# Verbose mode shows detailed execution information
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --verbose
# Output includes:
# - Tool discovery progress
# - Individual test execution details
# - Safety system actions
# - Performance metrics
```

### Error Handling and Recovery

#### Graceful Error Handling

The CLI handles errors gracefully with proper cleanup:

```bash
# Interrupt handling (Ctrl+C)
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --runs 100
# Press Ctrl+C
# Output: "Fuzzing interrupted. Cleaning up processes..."
#         "Use --retry-with-safety-on-interrupt to retry with safety enabled"
```

#### Retry Mechanisms

Built-in retry mechanisms for transient failures:

```bash
# Automatic retry on connection failures
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10
# If connection fails, automatically retries with exponential backoff
```

#### Safety Integration

Enhanced safety integration with better user feedback:

```bash
# Safety system status reporting
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --enable-safety-system
# Output: "Safety system enabled. Monitoring for dangerous operations..."
#         "Blocked 3 file operations outside sandbox"
#         "Safety report: 5 operations blocked, 2 warnings issued"
```

### Output Formatting Improvements

#### Rich Console Output

Enhanced console output with better formatting:

```bash
# Colorized output with better table formatting
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10
# Output includes:
# - Color-coded success/failure indicators
# - Progress bars for long operations
# - Formatted tables with proper alignment
# - Summary statistics with visual indicators
```

#### Report Generation

Improved report generation with better organization:

```bash
# Enhanced report generation
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --runs 20 \
    --safety-report \
    --export-safety-data \
    --output-dir "detailed_reports"
# Generates:
# - Comprehensive JSON report with metadata
# - Human-readable text summary
# - Safety-specific report with risk analysis
# - Session metadata and configuration
```

### Configuration Validation

#### Environment Variable Validation

The CLI validates environment variables and provides helpful messages:

```bash
# Invalid environment variable detection
export MCP_FUZZER_TIMEOUT="invalid"
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000
# Error: Invalid timeout value 'invalid'. Must be a positive number.
#        Current value: MCP_FUZZER_TIMEOUT=invalid
#        Suggested fix: export MCP_FUZZER_TIMEOUT=30.0
```

#### Configuration File Validation

Enhanced configuration file validation:

```bash
# Configuration file validation
mcp-fuzzer --mode tools --config invalid_config.yaml
# Error: Configuration file validation failed:
#        - Line 5: 'timeout' must be a number, got 'invalid'
#        - Line 10: 'protocol' must be one of ['http', 'sse', 'stdio', 'streamablehttp']
#        Suggested fixes:
#        - Fix timeout value on line 5
#        - Use valid protocol on line 10
```

### Performance Monitoring

#### Real-time Performance Metrics

The CLI provides real-time performance monitoring:

```bash
# Performance monitoring during execution
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 100 --verbose
# Output includes:
# - Requests per second
# - Average response time
# - Memory usage
# - CPU usage
# - Error rate trends
```

#### Resource Usage Reporting

Enhanced resource usage reporting:

```bash
# Resource usage summary
mcp-fuzzer --mode tools --protocol stdio --endpoint "python server.py" --runs 50
# Output: "Resource usage summary:"
#         "  CPU usage: 15.2% average"
#         "  Memory usage: 45.3 MB peak"
#         "  Network I/O: 2.1 MB total"
#         "  Process count: 3 managed"
```

### Debugging and Troubleshooting

#### Enhanced Debug Output

Improved debug output for troubleshooting:

```bash
# Debug mode with detailed information
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --log-level DEBUG
# Output includes:
# - Detailed request/response logging
# - Safety system decision logging
# - Process management events
# - Performance timing information
```

#### Diagnostic Information

Built-in diagnostic information for troubleshooting:

```bash
# System diagnostic information
mcp-fuzzer --diagnostics
# Output: "System Diagnostics:"
#         "  Python version: 3.9.7"
#         "  Platform: Linux x86_64"
#         "  Available protocols: http, sse, stdio, streamablehttp"
#         "  Safety system: available"
#         "  Network connectivity: OK"
```

## Additional Export Formats

The MCP Server Fuzzer supports multiple export formats for reports:

### CSV Export

Export fuzzing results to CSV format for analysis in spreadsheet applications:

```bash
# Export to CSV format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-csv results.csv

# Export with custom CSV configuration
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 \
    --export-csv results.csv \
    --csv-delimiter "," \
    --csv-quote-char "\""
```

CSV output includes:
- Tool name
- Run number
- Success status
- Response time
- Exception message (if any)
- Arguments used
- Timestamp

### XML Export

Export fuzzing results to XML format for integration with XML-based tools:

```bash
# Export to XML format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-xml results.xml

# Export with custom XML configuration
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 \
    --export-xml results.xml \
    --xml-indent 2 \
    --xml-encoding "utf-8"
```

### HTML Export

Export results to HTML format for web-based reporting:

```bash
# Export to HTML format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-html results.html

# Export with custom HTML template
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 \
    --export-html results.html \
    --html-template custom_template.html \
    --html-title "Fuzzing Results Report"
```

### Markdown Export

Export results to Markdown format for documentation:

```bash
# Export to Markdown format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-markdown results.md

# Export with custom Markdown configuration
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 \
    --export-markdown results.md \
    --markdown-style github \
    --markdown-toc true
```

### Export Format Options

#### CSV Options

| Option | Default | Description |
|--------|---------|-------------|
| `--csv-delimiter` | "," | Field delimiter |
| `--csv-quote-char` | "\"" | Quote character |
| `--csv-escape-char` | "\\" | Escape character |
| `--csv-line-terminator` | "\\n" | Line terminator |

#### XML Options

| Option | Default | Description |
|--------|---------|-------------|
| `--xml-indent` | 2 | Indentation spaces |
| `--xml-encoding` | "utf-8" | Character encoding |
| `--xml-root-name` | "fuzzing_results" | Root element name |
| `--xml-attribute-quotes` | "double" | Attribute quote style |

#### HTML Options

| Option | Default | Description |
|--------|---------|-------------|
| `--html-template` | "default" | HTML template to use |
| `--html-title` | "Fuzzing Results" | Page title |
| `--html-css` | "default" | CSS style to apply |
| `--html-js` | "default" | JavaScript to include |

#### Markdown Options

| Option | Default | Description |
|--------|---------|-------------|
| `--markdown-style` | "default" | Markdown style (github, gitlab, etc.) |
| `--markdown-toc` | false | Include table of contents |
| `--markdown-toc-depth` | 3 | TOC depth |
| `--markdown-code-style` | "fenced" | Code block style |

### Export Format Comparison

| Format | Use Case | Pros | Cons |
|--------|----------|------|------|
| **JSON** | API integration, programmatic analysis | Structured, machine-readable | Verbose, not human-readable |
| **CSV** | Spreadsheet analysis, data science | Simple, widely supported | Limited structure, no metadata |
| **XML** | Enterprise integration, complex data | Structured, extensible | Verbose, complex parsing |
| **HTML** | Web reporting, human-readable | Rich formatting, interactive | Not machine-readable |
| **Markdown** | Documentation, GitHub integration | Human-readable, version control friendly | Limited formatting |
| **Text** | Simple reporting, logs | Simple, universal | Limited structure |

### Export Format Comparison

| Format | Use Case | Pros | Cons |
|--------|----------|------|------|
| **JSON** | API integration, programmatic analysis | Structured, machine-readable | Verbose, not human-readable |
| **CSV** | Spreadsheet analysis, data science | Simple, widely supported | Limited structure, no metadata |
| **XML** | Enterprise integration, complex data | Structured, extensible | Verbose, complex parsing |
| **HTML** | Web reporting, human-readable | Rich formatting, interactive | Not machine-readable |
| **Markdown** | Documentation, GitHub integration | Human-readable, version control friendly | Limited formatting |
| **Text** | Simple reporting, logs | Simple, universal | Limited structure |

## Famous Open Source MCP Server Fuzz Results

For detailed fuzzing results and security analysis of popular open source MCP servers, see the [Fuzz Results](fuzz-results.md) documentation.

This section provides comprehensive testing results for various MCP server implementations, including vulnerability assessments, performance metrics, and security recommendations.

## API Reference
## API Reference

## Package Layout and Fuzz Engine

The codebase is organized around a modular fuzz engine with clear boundaries between generation (strategies), orchestration (fuzzers), and execution (runtime):

```
mcp_fuzzer/
  fuzz_engine/
    fuzzer/
      protocol_fuzzer.py   # Orchestrates protocol-type fuzzing
      tool_fuzzer.py       # Orchestrates tool fuzzing
    strategy/
      schema_parser.py     # JSON Schema parser for test data generation
      strategy_manager.py  # Selects strategies per phase/type
      realistic/
        tool_strategy.py
        protocol_type_strategy.py
      aggressive/
        tool_strategy.py
        protocol_type_strategy.py
    invariants.py         # Property-based invariants and checks
    runtime/
      manager.py           # Async ProcessManager (start/stop, signals)
      watchdog.py          # ProcessWatchdog (hang detection)
      wrapper.py           # Async helpers/executor wrapper
  transport/
    base.py                # TransportProtocol interface
    http.py                # JSON over HTTP
    sse.py                 # Server-Sent Events
    stdio.py               # STDIO transport
    streamable_http.py     # Streamable HTTP (JSON + SSE, session headers)
    factory.py             # create_transport(...)
  reports/
    reporter.py            # Aggregates results
    formatters.py          # Console/JSON/Text formatters
    safety_reporter.py     # Safety-specific report
  safety_system/
    safety.py              # Argument-level filtering/sanitization
    system_blocker.py      # System-level command blocking
  cli/
    args.py, main.py, runner.py
  client.py                # UnifiedMCPFuzzerClient orchestrator
```

## Schema Parser

The schema parser module (`mcp_fuzzer.fuzz_engine.strategy.schema_parser`) provides comprehensive support for parsing JSON Schema definitions and generating appropriate test data based on schema specifications.

### Features

- **Basic Types**: Handles string, number, integer, boolean, array, object, and null types
- **String Constraints**: Supports minLength, maxLength, pattern, and format validations
- **Number/Integer Constraints**: Handles minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf
- **Array Constraints**: Supports minItems, maxItems, uniqueItems
- **Object Constraints**: Handles required properties, minProperties, additionalProperties (false blocks extra properties)
- **Schema Combinations**: Processes oneOf, anyOf, allOf schema combinations with proper constraint merging
- **Enums and Constants**: Supports enum values and const keyword (both in realistic and aggressive modes)
- **Fuzzing Phases**: Supports both "realistic" (valid) and "aggressive" (edge cases) modes

### Example Usage

```python
from mcp_fuzzer.fuzz_engine.strategy.schema_parser import make_fuzz_strategy_from_jsonschema

# Define a JSON schema
schema = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 3, "maxLength": 50},
        "age": {"type": "integer", "minimum": 18, "maximum": 120},
        "email": {"type": "string", "format": "email"}
    },
    "required": ["name", "age"]
}

# Generate realistic data
realistic_data = make_fuzz_strategy_from_jsonschema(schema, phase="realistic")

# Generate aggressive data for security testing
aggressive_data = make_fuzz_strategy_from_jsonschema(schema, phase="aggressive")
```

## Invariants System

The invariants module (`mcp_fuzzer.fuzz_engine.invariants`) provides property-based testing capabilities to verify response validity, error type correctness, and prevention of unintended crashes or unexpected states during fuzzing.

### Features

- **Response Validity**: Ensures responses follow JSON-RPC 2.0 specification
- **Error Type Correctness**: Verifies error responses have correct structure and codes
- **Schema Conformity**: Validates responses against JSON schema definitions
- **Batch Verification**: Applies invariant checks to batches of responses
- **State Consistency**: Ensures server state remains consistent during fuzzing

### Example Usage

```python
from mcp_fuzzer.fuzz_engine.invariants import verify_response_invariants, InvariantViolation

# Verify a response against invariants
try:
    verify_response_invariants(
        response={"jsonrpc": "2.0", "id": 1, "result": "success"},
        expected_error_codes=[400, 404, 500],
        schema={"type": "object", "properties": {"result": {"type": "string"}}}
    )
    # Response is valid
except InvariantViolation as e:
    # Invariant violation detected
    print(f"Violation: {e}")
```

- Strategy: Generates inputs for tools and protocol types in two phases:
  - realistic (valid/spec-conformant), aggressive (malformed/attack vectors).
- Fuzzer: Runs strategies, sends envelopes via a transport, and records results.
- Runtime: Manages subprocess lifecycles with a watchdog for hang/timeout handling.
- Transport: Pluggable I/O. Use `--protocol http|sse|stdio|streamablehttp`.

### Fuzz Engine lifecycle (high level)

- Client builds a `TransportProtocol` via the factory.
- For tools: `ToolFuzzer` selects a strategy (phase), generates args, invokes `tools/call`.
- For protocol: `ProtocolFuzzer` selects a message type, generates the JSON-RPC envelope, sends raw via the transport.
- Runtime ensures external processes (when used) are supervised and terminated safely.

## Runtime

The runtime layer provides robust, asynchronous subprocess lifecycle management for transports and target servers under test.

- Components:
  - `ProcessManager` (async): start/stop processes, send signals, await exit, collect stats; integrates with the watchdog.
  - `ProcessWatchdog`: monitors registered PIDs for hangs/inactivity and terminates them based on policy.
  - All operations are now fully asynchronous using native asyncio.

- Behavior and guarantees:

  - Fully async API; blocking calls (spawn, wait, kill) run in thread executors.
  - Process-group signaling on POSIX to prevent orphan children.
  - Safe stop flow: TERM (grace window) → KILL on timeout if needed.
  - Watchdog auto-starts on first registration/start; auto-unregisters on stop.

- Typical usage:

  - Transports that spawn servers should use `ProcessManager.start_process(...)` and register activity callbacks.
  - For externally spawned subprocesses (e.g., `asyncio.create_subprocess_exec`), register with the watchdog to enable hang detection and timeouts.

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
        "total_protocol_types": 19,
        "total_runs": 95,
        "overall_success_rate": 93.3,
        "total_exceptions": 5
    }
}
```

## Safety System Reference

The safety system focuses on containment and preventing external references during fuzzing.

- Argument-level filtering (`mcp_fuzzer.safety_system.safety.SafetyFilter`):
  - Blocks URLs and risky commands in tool arguments; recursively sanitizes dicts/lists.
  - Pluggable provider via `--safety-plugin`; `--no-safety` disables filtering.
  - `set_fs_root(path)` records a sandbox root (for future path checks).

- System-level blocking (`mcp_fuzzer.safety_system.system_blocker.SystemCommandBlocker`):
  - Creates PATH shims for `xdg-open`, `open`, and browsers to prevent app launches.
  - Enabled with `--enable-safety-system`; cleaned up on exit.

- Policy utilities (`mcp_fuzzer.safety_system.policy`):
  - `is_host_allowed(url, allowed_hosts=None, deny_network_by_default=None)`
  - `resolve_redirect_safely(base_url, location, ...)` (same-origin + allow-list)
  - `sanitize_subprocess_env(env)` strips proxy env vars before spawning subprocesses
  - `sanitize_headers(headers)` removes sensitive outbound headers by default

- **Safety Options (CLI Flags)**:
  - `--no-network`: Disallow non-local hosts.
  - `--allow-host HOST`: Add to allow-list (bare hostname/IP, no scheme/port). Repeatable.

- **Network and Proxy Policies**:
  - HTTP transports are created with environment proxies disabled (`trust_env=False`), so environment proxy variables are ignored.
  - Only same-origin 307 and 308 redirects are automatically followed, and only after checking the host allow-list policy via `is_host_allowed`.

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
