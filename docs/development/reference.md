# Reference

This page provides a complete reference for MCP Server Fuzzer, including all command-line options, API documentation, and configuration details.

## Command-Line Reference

### Basic Syntax

```bash
mcp-fuzzer [OPTIONS] --mode {tools|protocol|resources|prompts|all} --protocol {http|sse|stdio|streamablehttp} --endpoint ENDPOINT
```

### Global Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--help` | Flag | - | Show help message and exit |
| `--verbose` | Flag | False | Enable verbose logging |
| `--log-level` | Choice | WARNING (INFO with `--verbose`) | Set log level (CRITICAL, ERROR, WARNING, INFO, DEBUG). Defaults to WARNING, or INFO when `--verbose` is set |

### Utility Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--validate-config` | Path | - | Validate configuration file and exit |
| `--check-env` | Flag | False | Validate environment variables and exit |

### Mode Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `--mode` | Choice | Yes | Fuzzing mode: `tools`, `protocol`, `resources`, `prompts`, or `all` |
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
| `--runs-per-type` | Integer | 5 | Number of runs per protocol/resource/prompt type |
| `--protocol-type` | String | - | Fuzz only a specific protocol type (protocol mode only; required by the CLI when using `--mode protocol`) |

### Spec Guard Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--spec-guard` | Bool | True | Run deterministic spec guard checks before protocol/resources/prompts fuzzing |
| `--spec-resource-uri` | String | - | Resource URI used for spec guard resources/read checks |
| `--spec-prompt-name` | String | - | Prompt name used for spec guard prompts/get checks |
| `--spec-prompt-args` | String | - | JSON string of prompt arguments for spec guard prompts/get checks |

### Safety Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--enable-safety-system` | Flag | False | Enable system-level safety features |
| `--no-safety` | Flag | False | Disable argument-level safety filtering |
| `--fs-root` | Path | ~/.mcp_fuzzer | Restrict filesystem operations to specified directory |
| `--retry-with-safety-on-interrupt` | Flag | False | Retry once with safety system enabled on Ctrl-C |

### Network Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--no-network` | Flag | False | Disallow network to non-local hosts |
| `--allow-host` | String | - | Permit additional hostnames when `--no-network` is set (repeatable) |

### Reporting Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--output-dir` | Path | reports | Directory to save reports and exports |
| `--safety-report` | Flag | False | Show comprehensive safety report at end of fuzzing |
| `--export-safety-data` | String | - | Export safety data to JSON file (optional filename) |
| `--output-format` | Choice | json | Output format for standardized reports |
| `--output-types` | List | - | Output types to generate (fuzzing_results, error_report, safety_summary, performance_metrics, configuration_dump) |
| `--output-schema` | Path | - | Path to custom output schema file |
| `--output-compress` | Flag | False | Compress output files |
| `--output-session-id` | String | - | Custom session ID for output files |

Notes:

- Standardized output files are currently emitted as JSON; `--output-format` is accepted for compatibility.

### Export Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--export-csv` | Path | - | Export fuzzing results to CSV format |
| `--export-xml` | Path | - | Export fuzzing results to XML format |
| `--export-html` | Path | - | Export fuzzing results to HTML format |
| `--export-markdown` | Path | - | Export fuzzing results to Markdown format |

### Runtime Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--watchdog-check-interval` | Float | 1.0 | How often to check processes for hanging (seconds) |
| `--watchdog-process-timeout` | Float | 30.0 | Time before a process is considered hanging (seconds) |
| `--watchdog-extra-buffer` | Float | 5.0 | Extra time before auto-kill (seconds) |
| `--watchdog-max-hang-time` | Float | 60.0 | Maximum time before force kill (seconds) |
| `--process-max-concurrency` | Integer | 5 | Maximum concurrent process operations |
| `--max-concurrency` | Integer | 5 | Maximum concurrent client operations |
| `--process-retry-count` | Integer | 1 | Number of retries for failed operations |
| `--process-retry-delay` | Float | 1.0 | Delay between retries (seconds) |

### Advanced Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--tool-timeout` | Float | - | Per-tool call timeout in seconds (defaults to `--timeout` when unset) |
| `--enable-aiomonitor` | Flag | False | Enable AIOMonitor for async debugging (connect with `telnet localhost 20101`) |

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
| `MCP_PREFIX` | Prefix for API key value (default: Bearer) |
| `MCP_USERNAME` | Username for basic authentication |
| `MCP_PASSWORD` | Password for basic authentication |
| `MCP_OAUTH_TOKEN` | OAuth token for authentication |
| `MCP_CUSTOM_HEADERS` | Custom headers as JSON string for authentication |
| `MCP_TOOL_AUTH_MAPPING` | Map tool names to auth providers as JSON |

## Authentication System Reference

### Authentication Providers

The authentication system supports multiple provider types with configurable options:

#### API Key Authentication

```json
{
  "type": "api_key",
  "api_key": "YOUR_API_KEY",
  "header_name": "Authorization",
  "prefix": "Bearer"
}
```

- **api_key** (required): The API key value
- **header_name** (optional): HTTP header to place the key in (default: "Authorization")
- **prefix** (optional): Value prefix for the header (default: "Bearer"). Set to empty string for no prefix.

#### Basic Authentication

```json
{
  "type": "basic",
  "username": "user",
  "password": "password"
}
```

- **username** (required): Username for basic auth
- **password** (required): Password for basic auth

#### OAuth Token Authentication

```json
{
  "type": "oauth",
  "token": "YOUR_TOKEN",
  "token_type": "Bearer"
}
```

- **token** (required): OAuth token value
- **token_type** (optional): Token type for Authorization header (default: "Bearer")

#### Custom Headers Authentication

```json
{
  "type": "custom",
  "headers": {
    "X-Custom-Header": "value",
    "X-Another-Header": "another-value"
  }
}
```

- **headers** (required): Dictionary of custom headers to include

### Tool-to-Auth Mapping

Map specific tools to authentication providers:

```json
{
  "tool_mapping": {
    "openai_chat": "openai_api",
    "github_search": "github_api",
    "default_tool": "basic_auth"
  }
}
```

### Error Messages

The authentication system provides detailed error messages for configuration issues:

- Missing required fields indicate which provider type and field is missing
- Expected configuration format is provided in error messages
- Type validation errors show the received vs. expected type

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

- `async wait(pid: int, timeout: Optional[float] = None) -> Optional[int]`
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

- `async register_existing_process(pid: int, process: asyncio.subprocess.Process, name: Optional[str] = None, activity_callback: Optional[Callable[[], float]] = None, *, config: Optional[ProcessConfig] = None) -> None`
  - Register an already-started subprocess with the manager
  - Useful for integrating with existing process management

#### Usage Examples

```python
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig

async def process_manager_example():
    manager = ProcessManager.from_config()

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
  - Start the watchdog monitoring loop; creates background task for monitoring

- `async stop() -> None`
  - Stop the monitoring loop and cancel/await the background task

- `async scan_once(processes: dict[int, ProcessRecord]) -> dict[str, Any]`
  - Run one hang-detection pass against a registry snapshot

- `async update_activity(pid: int) -> None`
  - Update activity timestamp for a process pulled from the registry

- `async get_stats() -> dict`
  - Get statistics about monitored processes and the watchdog loop state

Note: processes are added to the shared `ProcessRegistry` (or by
`ProcessLifecycle.start`), and the watchdog reads that registry instead of
maintaining its own table.

#### Context Manager Support

```python
async with ProcessWatchdog(registry, dispatcher, config) as watchdog:
    await registry.register(pid, process, ProcessConfig(command=["python"], name=name))
    await watchdog.update_activity(pid)
    # ... registry keeps the process table; watchdog reads it
```

#### Usage Examples

```python
import asyncio
import logging
from mcp_fuzzer.fuzz_engine.runtime import (
    ProcessConfig,
    ProcessRegistry,
    ProcessWatchdog,
    SignalDispatcher,
    WatchdogConfig,
)

async def watchdog_example():
    registry = ProcessRegistry()
    dispatcher = SignalDispatcher(registry, logging.getLogger(__name__))
    watchdog = ProcessWatchdog(
        registry,
        dispatcher,
        WatchdogConfig(check_interval=1.0, process_timeout=30.0, auto_kill=True),
    )
    await watchdog.start()

    # Register a process via the registry
    process = await asyncio.create_subprocess_exec("python", "server.py")
    await registry.register(
        process.pid,
        process,
        ProcessConfig(command=["python", "server.py"], name="server"),
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

The `AsyncFuzzExecutor` provides controlled concurrency for fuzzing operations using semaphore-based concurrency control.

#### Class Definition

```python
class AsyncFuzzExecutor:
    def __init__(
        self,
        max_concurrency: int = 5,      # Maximum concurrent operations
    ):
```

#### Methods

- `async execute_batch(operations: List[Tuple[Callable, List[Any], Dict[str, Any]]]) -> Dict[str, List[Any]]`
  - Execute a batch of operations concurrently with bounded concurrency
  - Operations are tuples of `(callable, args, kwargs)`
  - Returns dictionary with `'results'` and `'errors'` lists
  - Errors are automatically collected; successful results in `'results'`
  - Handles both async and sync operations (sync runs in thread pool)

- `async run_hypothesis_strategy(strategy: st.SearchStrategy) -> Any`
  - Run a Hypothesis strategy in thread pool to prevent asyncio deadlocks
  - Returns generated value from the strategy

- `async shutdown() -> None`
  - Shutdown the executor and clean up thread pool resources
  - Waits for thread pool to complete all tasks

#### Usage Examples

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def executor_example():
    executor = AsyncFuzzExecutor(max_concurrency=3)

    try:
        # Define async operation
        async def sample_operation(value):
            await asyncio.sleep(0.5)
            return f"processed_{value}"

        # Prepare operations as (function, args, kwargs) tuples
        operations = [
            (sample_operation, [i], {}) for i in range(10)
        ]

        # Execute batch with automatic error collection
        results = await executor.execute_batch(operations)

        print(f"Results: {len(results['results'])}, Errors: {len(results['errors'])}")

    finally:
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
```

### Argument Validation

The CLI now validates argument combinations and provides helpful error messages:

```bash
# Invalid combination detection
mcp-fuzzer --mode protocol
# Error: --protocol-type is required when --mode protocol

# Missing required arguments
mcp-fuzzer --mode tools
# Error: --endpoint is required for fuzzing operations
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

## Additional Export Formats

The MCP Server Fuzzer supports multiple export formats for reports:

### CSV Export

Export fuzzing results to CSV format for analysis in spreadsheet applications:

```bash
# Export to CSV format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-csv results.csv
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
```

### HTML Export

Export results to HTML format for web-based reporting:

```bash
# Export to HTML format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-html results.html
```

### Markdown Export

Export results to Markdown format for documentation:

```bash
# Export to Markdown format
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 20 --export-markdown results.md
```

Notes:

- JSON and text reports are always written to `--output-dir`.
- Export flags create additional artifacts in the same output directory.

### Export Format Comparison

| Format | Use Case | Notes |
|--------|----------|-------|
| **JSON** | Programmatic analysis | Generated automatically in the output directory |
| **CSV** | Spreadsheet analysis | Simple tabular summary |
| **XML** | Enterprise integration | Structured, verbose |
| **HTML** | Web reporting | Human-readable |
| **Markdown** | Documentation | Works well in repos and wikis |

## Famous Open Source MCP Server Fuzz Results

For detailed fuzzing results and security analysis of popular open source MCP servers, see the [Fuzz Results](fuzz-results.md) documentation.

This section provides comprehensive testing results for various MCP server implementations, including vulnerability assessments, performance metrics, and security recommendations.

## API Reference

## Package Layout and Fuzz Engine

The codebase is organized around a modular fuzz engine with clear boundaries between generation (mutators), orchestration (executors), and execution (runtime):

```
mcp_fuzzer/
  fuzz_engine/
    mutators/
      tool_mutator.py       # Generates fuzzed tool arguments
      protocol_mutator.py   # Generates fuzzed protocol envelopes
      batch_mutator.py      # Generates JSON-RPC batch requests
      strategies/
        schema_parser.py    # JSON Schema parser for test data generation
        strategy_manager.py # Realistic/aggressive strategy selection
        realistic/
          tool_strategy.py
          protocol_type_strategy.py
        aggressive/
          tool_strategy.py
          protocol_type_strategy.py
    executor/
      tool_executor.py      # Orchestrates tool fuzzing (uses AsyncFuzzExecutor)
      protocol_executor.py  # Orchestrates protocol-type fuzzing + invariants
      batch_executor.py     # Orchestrates batch fuzzing
      invariants.py         # Property-based invariants and checks
    runtime/
      manager.py           # Async ProcessManager (start/stop, signals)
      watchdog.py          # ProcessWatchdog (hang detection)
      wrapper.py           # Async helpers/executor wrapper
  transport/
    interfaces/driver.py   # TransportDriver interface
    drivers/http_driver.py # JSON over HTTP
    drivers/sse_driver.py  # Server-Sent Events
    drivers/stdio_driver.py # STDIO transport
    drivers/stream_http_driver.py # Streamable HTTP (JSON + SSE, session headers)
    catalog/builder.py     # build_driver(...)
  reports/
    reporter/              # Aggregates results + DI plumbing
    formatters/            # Console/JSON/Text/HTML/etc. formatters
    output/                # Standardized output protocol + manager
    safety_reporter.py     # Safety-specific report
  safety_system/
    safety.py              # SafetyFilter and SafetyProvider protocol
    blocking/             # PATH shim command blocker + shims
      command_blocker.py
      shims/
    detection/            # DangerDetector patterns and helpers
      detector.py
      patterns.py
    filesystem/           # Filesystem sandbox + path sanitizer
      sandbox.py
      sanitizer.py
  cli/
    parser.py, entrypoint.py, validators.py, config_merge.py
  client/
    main.py               # UnifiedMCPFuzzerClient orchestrator
```

## Schema Parser

The schema parser module (`mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser`) provides comprehensive support for parsing JSON Schema definitions and generating appropriate test data based on schema specifications.

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
from mcp_fuzzer.fuzz_engine.mutators.strategies.schema_parser import (
    make_fuzz_strategy_from_jsonschema
)

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

The invariants module (`mcp_fuzzer.fuzz_engine.executor.invariants`) provides property-based testing capabilities to verify response validity, error type correctness, and prevention of unintended crashes or unexpected states during fuzzing.

### Features

- **Response Validity**: Ensures responses follow JSON-RPC 2.0 specification
- **Error Type Correctness**: Verifies error responses have correct structure and codes
- **Schema Conformity**: Validates responses against JSON schema definitions
- **Batch Verification**: Applies invariant checks to batches of responses
- **State Consistency**: Ensures server state remains consistent during fuzzing

### Example Usage

```python
from mcp_fuzzer.fuzz_engine.executor.invariants import (
    verify_response_invariants,
    InvariantViolation
)

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

- Mutators: Generate inputs for tools and protocol types in two phases:
  - realistic (valid/spec-conformant), aggressive (malformed/attack vectors).
- Executors: Run mutators, send envelopes via a transport, and record results.
- Runtime: Manages subprocess lifecycles with a watchdog for hang/timeout handling.
- Transport: Pluggable I/O. Use `--protocol http|sse|stdio|streamablehttp`.

### Fuzz Engine lifecycle (high level)

- Client builds a `TransportDriver` via the factory.
- For tools: `ToolExecutor` orchestrates `ToolMutator` to generate args, integrates with safety system, and executes via transport.
- For protocol: `ProtocolExecutor` orchestrates `ProtocolMutator` to generate JSON-RPC envelopes, validates invariants, and sends raw via transport.
- All executors use `AsyncFuzzExecutor` for concurrent execution with bounded concurrency.
- Runtime ensures external processes (when used) are supervised and terminated safely.

See [Fuzz Engine Architecture](../architecture/fuzz-engine.md) for detailed information about the modular design.

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
  - Watchdog uses the shared registry; call `start()`/`stop()` explicitly (or via context manager) and unregisters completed/hung processes after a scan.

- Typical usage:

  - Transports that spawn servers should use `ProcessManager.start_process(...)` and register activity callbacks.
  - For externally spawned subprocesses (e.g., `asyncio.create_subprocess_exec`), register with the watchdog to enable hang detection and timeouts.

### Transport Protocol Interface

The core interface for transport protocols:

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, AsyncIterator

class TransportDriver(ABC):
    """Abstract base class for transport protocols."""

    @abstractmethod
    async def send_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC request to the server."""
        pass

    @abstractmethod
    async def send_raw(self, payload: Dict[str, Any]) -> Any:
        """Send raw payload to the server."""
        pass

    @abstractmethod
    async def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Send a JSON-RPC notification to the server."""
        pass

    async def connect(self) -> None:
        """Connect to the transport (optional override)."""
        pass

    async def disconnect(self) -> None:
        """Disconnect from the transport (optional override)."""
        pass

    async def stream_request(self, payload: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        """Stream a request and yield response chunks."""
        pass

    @abstractmethod
    async def _stream_request(self, payload: Dict[str, Any]) -> AsyncIterator[Dict[str, Any]]:
        """Transport-specific streaming implementation."""
        pass
```

### Fuzzer Client

The main client for orchestrating fuzzing operations:

```python
from mcp_fuzzer.client import MCPFuzzerClient
from mcp_fuzzer.safety_system.safety import SafetyFilter

class UnifiedMCPFuzzerClient:
    """Unified client for MCP fuzzing operations."""

    def __init__(
        self,
        transport: TransportDriver,
        safety_system: Optional[SafetyFilter] = None,
    ):
        self.transport = transport
        self.safety_system = safety_system or SafetyFilter()

    async def fuzz_tools(self, runs: int = 10, phase: str = "aggressive"):
        """Fuzz tools with specified number of runs and phase."""
        # Implementation details mirror mcp_fuzzer.client.base.MCPFuzzerClient

    async def fuzz_protocol(
        self, runs_per_type: int = 5, protocol_type: Optional[str] = None, phase: str = "aggressive"
    ):
        """Fuzz protocol types with specified parameters."""
        # Implementation details...
```

### Safety System

Core safety system for protecting against dangerous operations:

```python
from mcp_fuzzer.safety_system.safety import SafetyFilter

safety = SafetyFilter()
safety.set_fs_root("/tmp/mcp_sandbox")

tool_args = {"url": "https://example.com", "output_path": "/etc/passwd"}
sanitized = safety.sanitize_tool_arguments("web_tool", tool_args)

if safety.should_skip_tool_call("web_tool", tool_args):
    safe_response = safety.create_safe_mock_response("web_tool")
else:
    # Proceed with sanitized arguments
    transport.call_tool("web_tool", sanitized)
```

`SafetyFilter` combines the pattern-based `DangerDetector`, filesystem path
sanitization, and blocked operation logging. For system-level protection call
`mcp_fuzzer.safety_system.blocking.start_system_blocking()` to install PATH
shims that intercept browser launches.

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
  - CLI provides `--fs-root` to redirect sandbox.
  - `set_fs_root(path)` records a sandbox root (for future path checks).

- System-level blocking (`mcp_fuzzer.safety_system.blocking.command_blocker.SystemCommandBlocker`):
  - Creates PATH shims for `xdg-open`, `open`, `start`, and common browsers to prevent app launches.
  - Enabled with `--enable-safety-system`; helper functions live in `mcp_fuzzer.safety_system.blocking`.

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
  "tool_mapping": {
    "openai_chat": "openai_api",
    "github_search": "github_api",
    "secure_tool": "basic_auth"
  }
}
```

This reference covers all the major aspects of MCP Server Fuzzer. For more detailed information about specific components, see the [Architecture](architecture.md) and [Examples](examples.md) documentation.
