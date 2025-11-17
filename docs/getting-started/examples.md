# Examples

This page provides working examples and configurations for common use cases with MCP Server Fuzzer.

## Basic Examples

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

## Authentication Examples

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
  "tool_mapping": {
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

## Safety System Examples

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
# Retry with safety on interrupt
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --retry-with-safety-on-interrupt

# Combined safety options
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" \
  --enable-safety-system \
  --fs-root /tmp/safe_dir \
  --retry-with-safety-on-interrupt
```

## Fuzzing Strategy Examples

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

## Configuration Examples

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

## Testing Examples

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

## Custom Transport Examples

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
from mcp_fuzzer.client import MCPFuzzerClient

# Create custom transport
transport = CustomTransport("custom-endpoint")

# Use with fuzzer client (with optional concurrency control)
client = MCPFuzzerClient(
    transport,
    max_concurrency=10  # Optional: Control concurrent operations
)

# Run fuzzing
await client.fuzz_tools(runs=10)
```

## Reporting Examples

### Basic Reporting

```bash
# Generate reports in default 'reports' directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10

# Specify custom output directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --output-dir "my_reports"

# Generate comprehensive safety report
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --safety-report
```

### Advanced Reporting

```bash
# Export safety data to JSON with custom filename
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 --export-safety-data "safety_data.json"

# Combine all reporting features
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 10 \
    --safety-report \
    --export-safety-data \
    --output-dir "detailed_reports"
```

### Generated Report Files

Each fuzzing session creates timestamped reports:

```text
reports/
| -- fuzzing_report_20250812_143000.json    # Complete structured data
| -- fuzzing_report_20250812_143000.txt     # Human-readable summary
| -- safety_report_20250812_143000.json     # Safety system data
```

### Report Content Examples

#### JSON Report Structure
```json
{
  "metadata": {
    "session_id": "20250812_143000",
    "start_time": "2025-08-12T14:30:00.123456",
    "mode": "tools",
    "protocol": "stdio",
    "endpoint": "python server.py",
    "runs": 10,
    "fuzzer_version": "1.0.0",
    "end_time": "2025-08-12T14:30:15.654321"
  },
  "tool_results": {
    "test_tool": [
      {"run": 1, "success": true, "args": {...}},
      {"run": 2, "success": false, "exception": "Invalid argument"}
    ]
  },
  "summary": {
    "tools": {
      "total_tools": 1,
      "total_runs": 10,
      "success_rate": 80.0
    }
  }
}
```

#### Text Report Example
```text
================================================================================
MCP FUZZER REPORT
================================================================================

FUZZING SESSION METADATA
----------------------------------------
session_id: 20250812_143000
start_time: 2025-08-12T14:30:00.123456
mode: tools
protocol: stdio
endpoint: python server.py
runs: 10

SUMMARY STATISTICS
----------------------------------------
Tools Tested: 1
Total Tool Runs: 10
Tools with Errors: 0
Tools with Exceptions: 2
Tool Success Rate: 80.0%
```

## Debugging Examples

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

## Output Examples

### Tool Fuzzer Output

```
+------------------------------------------------------------------------------+
|                              Tool Fuzzer Results                               |
+------------------------------------------------------------------------------+
| Tool Name        | Success Rate | Exception Count | Example Exceptions        |
+------------------------------------------------------------------------------+
| get_weather      | 85.0%        | 3               | Invalid city name        |
| search_web       | 92.0%        | 1               | Network timeout          |
| calculate_math   | 100.0%       | 0               | None                     |
+------------------------------------------------------------------------------+
| Overall          | 92.3%        | 4               | 3 tools tested           |
+------------------------------------------------------------------------------+
```

### Protocol Fuzzer Output

```
+------------------------------------------------------------------------------+
|                           Protocol Fuzzer Results                              |
+------------------------------------------------------------------------------+
| Protocol Type        | Total Runs | Successful | Exceptions | Success Rate |
+------------------------------------------------------------------------------+
| InitializeRequest    | 5          | 5          | 0          | 100.0%       |
| ProgressNotification | 5          | 4          | 1          | 80.0%        |
| CancelNotification   | 5          | 5          | 0          | 100.0%       |
+------------------------------------------------------------------------------+
| Overall              | 15         | 14         | 1          | 93.3%        |
+------------------------------------------------------------------------------+
```

## Runtime Management Examples

### Process Management with Watchdog

#### Basic Process Management

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.watchdog import WatchdogConfig

async def basic_process_management():
    # Configure watchdog
    watchdog_config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=30.0,
        auto_kill=True
    )

    # Create process manager
    manager = ProcessManager(watchdog_config)

    try:
        # Start a test server
        config = ProcessConfig(
            command=["python", "test_server.py"],
            name="test_server",
            timeout=60.0
        )
        process = await manager.start_process(config)

        # Monitor process
        status = await manager.get_process_status(process.pid)
        print(f"Process {process.pid} status: {status['status']}")

        # Let it run for a while
        await asyncio.sleep(10)

        # Stop gracefully
        await manager.stop_process(process.pid)

    finally:
        await manager.shutdown()
```

#### Process with Activity Monitoring

```python
import time

async def process_with_activity_monitoring():
    manager = ProcessManager()

    # Activity callback for hang detection
    last_activity = time.time()

    def activity_callback():
        nonlocal last_activity
        return last_activity

    def update_activity():
        nonlocal last_activity
        last_activity = time.time()

    config = ProcessConfig(
        command=["python", "long_running_server.py"],
        name="long_server",
        activity_callback=activity_callback,
        timeout=120.0
    )

    process = await manager.start_process(config)

    try:
        # Simulate periodic activity updates
        for i in range(20):
            update_activity()
            await manager.update_activity(process.pid)
            await asyncio.sleep(2)

    finally:
        await manager.stop_process(process.pid)
        await manager.shutdown()
```

#### Multiple Process Management

```python
async def multiple_process_management():
    manager = ProcessManager()

    try:
        # Start multiple worker processes
        processes = []
        for i in range(3):
            config = ProcessConfig(
                command=["python", f"worker_{i}.py"],
                name=f"worker_{i}",
                timeout=30.0
            )
            process = await manager.start_process(config)
            processes.append(process)

        # Monitor all processes
        all_processes = await manager.list_processes()
        print(f"Managing {len(all_processes)} processes")

        # Get statistics
        stats = await manager.get_stats()
        print(f"Process statistics: {stats}")

        # Wait for all processes to complete
        await asyncio.sleep(30)

    finally:
        # Stop all processes
        await manager.stop_all_processes()
        await manager.shutdown()
```

### AsyncFuzzExecutor Examples

#### Basic Executor Usage

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def basic_executor_usage():
    executor = AsyncFuzzExecutor(
        max_concurrency=3,
        timeout=10.0,
        retry_count=2
    )

    try:
        # Execute single operation
        async def sample_operation():
            await asyncio.sleep(1)
            return "success"

        result = await executor.execute(sample_operation)
        print(f"Result: {result}")

        # Execute with retry
        async def unreliable_operation():
            import random
            if random.random() < 0.5:
                raise Exception("Random failure")
            return "success"

        result = await executor.execute_with_retry(unreliable_operation)
        print(f"Result after retries: {result}")

    finally:
        await executor.shutdown()
```

#### Batch Operations with Error Handling

```python
async def batch_operations_example():
    executor = AsyncFuzzExecutor(max_concurrency=5)

    try:
        # Define multiple operations
        operations = []
        for i in range(10):
            async def operation(x=i):
                await asyncio.sleep(0.1)
                if x % 3 == 0:  # Some operations fail
                    raise Exception(f"Operation {x} failed")
                return f"result_{x}"

            operations.append((operation, [], {}))

        # Execute batch with error collection
        results = await executor.execute_batch(
            operations,
            collect_results=True,
            collect_errors=True
        )

        print(f"Successful results: {len(results['results'])}")
        print(f"Errors: {len(results['errors'])}")

        # Process successful results
        for result in results['results']:
            print(f"Success: {result}")

        # Handle errors
        for error in results['errors']:
            print(f"Error: {error}")

    finally:
        await executor.shutdown()
```

#### Custom Timeout and Concurrency

```python
async def custom_executor_configuration():
    # High concurrency for I/O-bound operations
    io_executor = AsyncFuzzExecutor(
        max_concurrency=20,
        timeout=30.0,
        retry_count=1
    )

    # Low concurrency for CPU-bound operations
    cpu_executor = AsyncFuzzExecutor(
        max_concurrency=4,
        timeout=60.0,
        retry_count=0
    )

    try:
        # I/O-bound operations
        async def io_operation():
            await asyncio.sleep(0.1)  # Simulate I/O
            return "io_result"

        # CPU-bound operations
        async def cpu_operation():
            # Simulate CPU work off the event loop
            return await asyncio.to_thread(lambda: (sum(range(1_000_000)), "cpu_result"))[1]

        # Execute with appropriate executor
        io_results = await io_executor.execute_batch([
            (io_operation, [], {}) for _ in range(20)
        ])

        cpu_results = await cpu_executor.execute_batch([
            (cpu_operation, [], {}) for _ in range(4)
        ])

        print(f"IO results: {len(io_results['results'])}")
        print(f"CPU results: {len(cpu_results['results'])}")

    finally:
        await io_executor.shutdown()
        await cpu_executor.shutdown()
```

## Enhanced Reporting Examples

### Comprehensive Safety Reporting

```bash
# Generate comprehensive safety report
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 20 --safety-report

# Export safety data to JSON
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 20 --export-safety-data

# Combine safety reporting with custom output directory
mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 20 \
    --safety-report \
    --export-safety-data \
    --output-dir "detailed_safety_reports"
```

### Advanced Report Analysis

#### JSON Report Processing

```python
import json
from datetime import datetime

def analyze_fuzzing_report(report_path):
    with open(report_path, 'r') as f:
        report = json.load(f)

    # Extract metadata
    metadata = report['metadata']
    print(f"Session: {metadata['session_id']}")
    print(f"Mode: {metadata['mode']}")
    start = datetime.fromisoformat(metadata['start_time'])
    end = datetime.fromisoformat(metadata['end_time'])
    print(f"Duration: {end - start}")

    # Analyze tool results
    tool_results = report.get('tool_results', {})
    for tool_name, results in tool_results.items():
        success_count = sum(1 for r in results if r.get('success', False))
        total_count = len(results)
        success_rate = (success_count / total_count) * 100 if total_count > 0 else 0

        print(f"Tool {tool_name}: {success_rate:.1f}% success rate")

    # Analyze safety data
    safety_data = report.get('safety_data', {})
    if safety_data:
        blocked_operations = safety_data.get('blocked_operations', [])
        print(f"Blocked operations: {len(blocked_operations)}")

        for operation in blocked_operations[:5]:  # Show first 5
            print(f"  - {operation['operation']}: {operation['reason']}")

# Usage
analyze_fuzzing_report("reports/fuzzing_report_20250812_143000.json")
```

#### Safety Report Analysis

```python
import json
def analyze_safety_report(safety_report_path):
    with open(safety_report_path, 'r') as f:
        safety_report = json.load(f)

    # Analyze blocked operations by type
    blocked_by_type = {}
    for operation in safety_report.get('blocked_operations', []):
        op_type = operation.get('operation_type', 'unknown')
        blocked_by_type[op_type] = blocked_by_type.get(op_type, 0) + 1

    print("Blocked operations by type:")
    for op_type, count in blocked_by_type.items():
        print(f"  {op_type}: {count}")

    # Analyze risk levels
    risk_levels = safety_report.get('risk_assessments', {})
    print("\nRisk level distribution:")
    for level, count in risk_levels.items():
        print(f"  {level}: {count}")

    # Show recent blocked operations
    recent_blocks = safety_report.get('recent_blocks', [])
    print(f"\nRecent blocked operations ({len(recent_blocks)}):")
    for block in recent_blocks[-5:]:  # Last 5
        print(f"  - {block['timestamp']}: {block['operation']}")

# Usage
analyze_safety_report("reports/safety_report_20250812_143000.json")
```

### Custom Report Generation

#### Programmatic Report Creation

```python
from mcp_fuzzer.reports.reporter import FuzzerReporter
from mcp_fuzzer.reports.formatters import ConsoleFormatter, JSONFormatter, TextFormatter

async def custom_report_generation():
    # Create reporter with custom configuration
    reporter = FuzzerReporter(
        output_dir="custom_reports",
        enable_console=True,
        enable_json=True,
        enable_text=True
    )

    # Simulate fuzzing results
    tool_results = {
        "test_tool": [
            {"run": 1, "success": True, "args": {"param": "value1"}},
            {"run": 2, "success": False, "exception": "Invalid argument"},
            {"run": 3, "success": True, "args": {"param": "value2"}},
        ]
    }

    protocol_results = {
        "InitializeRequest": [
            {"run": 1, "success": True},
            {"run": 2, "success": True},
        ]
    }

    safety_data = {
        "blocked_operations": [
            {"operation": "file_write", "reason": "Outside sandbox", "timestamp": "2025-08-12T14:30:00"}
        ],
        "risk_assessments": {"high": 1, "medium": 0, "low": 0}
    }

    # Generate reports
    await reporter.generate_reports(
        tool_results=tool_results,
        protocol_results=protocol_results,
        safety_data=safety_data,
        metadata={
            "session_id": "custom_session",
            "mode": "tools",
            "protocol": "stdio",
            "runs": 3
        }
    )

    print("Custom reports generated in 'custom_reports' directory")
```

#### Report Comparison

```python
import json
def compare_reports(report1_path, report2_path):
    with open(report1_path, 'r') as f:
        report1 = json.load(f)

    with open(report2_path, 'r') as f:
        report2 = json.load(f)

    # Compare success rates
    def get_success_rate(report):
        tool_results = report.get('tool_results', {})
        total_success = 0
        total_runs = 0

        for tool_name, results in tool_results.items():
            success_count = sum(1 for r in results if r.get('success', False))
            total_success += success_count
            total_runs += len(results)

        return (total_success / total_runs * 100.0) if total_runs else 0.0

    rate1 = get_success_rate(report1)
    rate2 = get_success_rate(report2)

    print(f"Report 1 success rate: {rate1:.1f}%")
    print(f"Report 2 success rate: {rate2:.1f}%")
    print(f"Improvement: {rate2 - rate1:.1f} percentage points")

    # Compare safety data
    safety1 = report1.get('safety_data', {}).get('blocked_operations', [])
    safety2 = report2.get('safety_data', {}).get('blocked_operations', [])

    print(f"Report 1 blocked operations: {len(safety1)}")
    print(f"Report 2 blocked operations: {len(safety2)}")

# Usage
compare_reports(
    "reports/fuzzing_report_20250812_143000.json",
    "reports/fuzzing_report_20250812_150000.json"
)
```

## Performance Examples

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
These examples cover the most common use cases and should help you get started with MCP Server Fuzzer. For more advanced configurations and customizations, refer to the [Reference](reference.md), [Architecture](architecture.md), and [Runtime Management](runtime-management.md) documentation.
