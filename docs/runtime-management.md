# Runtime Management

This document provides comprehensive documentation for the MCP Server Fuzzer's runtime management system, including process management, watchdog monitoring, and async execution capabilities.

## Overview

The runtime management system provides robust, asynchronous subprocess lifecycle management for transports and target servers under test. It consists of three main components:

- **ProcessManager**: Fully async process lifecycle management
- **ProcessWatchdog**: Automated monitoring and termination of hanging processes
- **AsyncFuzzExecutor**: Controlled concurrency and error handling for fuzzing operations

## ProcessManager

The `ProcessManager` provides fully asynchronous subprocess lifecycle management with comprehensive process tracking and signal handling.

### Core Features

- **Async Process Creation**: Uses `asyncio.create_subprocess_exec` for non-blocking process spawning
- **Process Registration**: Automatically registers processes with the watchdog for monitoring
- **Signal Handling**: Supports graceful termination (SIGTERM) and force kill (SIGKILL) with process-group signaling
- **Status Tracking**: Maintains comprehensive process state including start time, status, and configuration
- **Cleanup Management**: Automatic cleanup of finished processes to prevent resource leaks

### Process Lifecycle

1. **Start**: Process is created with asyncio, registered with watchdog, and tracked in manager
2. **Monitor**: Watchdog monitors for hangs and inactivity using activity callbacks
3. **Stop**: Graceful termination with escalation to force kill if needed
4. **Cleanup**: Process is unregistered from watchdog and removed from tracking

### Configuration Options

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

### Usage Examples

#### Basic Process Management

```python
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig

async def basic_process_management():
    manager = ProcessManager()

    # Start a process
    config = ProcessConfig(
        command=["python", "test_server.py"],
        name="test_server",
        timeout=60.0
    )
    process = await manager.start_process(config)

    # Get process status
    status = await manager.get_process_status(process.pid)
    print(f"Process status: {status}")

    # Stop the process gracefully
    await manager.stop_process(process.pid)

    # Shutdown manager
    await manager.shutdown()
```

#### Process with Activity Monitoring

```python
import time

async def process_with_activity_monitoring():
    manager = ProcessManager()

    # Activity callback that reports current time
    def activity_callback():
        return time.time()

    config = ProcessConfig(
        command=["python", "long_running_server.py"],
        name="long_server",
        activity_callback=activity_callback,
        timeout=120.0
    )

    process = await manager.start_process(config)

    # Update activity periodically
    for _ in range(10):
        await manager.update_activity(process.pid)
        await asyncio.sleep(5)

    await manager.stop_process(process.pid)
    await manager.shutdown()
```

#### Multiple Process Management

```python
async def multiple_process_management():
    manager = ProcessManager()

    # Start multiple processes
    processes = []
    for i in range(3):
        config = ProcessConfig(
            command=["python", f"worker_{i}.py"],
            name=f"worker_{i}",
            timeout=30.0
        )
        process = await manager.start_process(config)
        processes.append(process)

    # List all processes
    all_processes = await manager.list_processes()
    print(f"Managing {len(all_processes)} processes")

    # Get overall statistics
    stats = await manager.get_stats()
    print(f"Process statistics: {stats}")

    # Stop all processes
    await manager.stop_all_processes()
    await manager.shutdown()
```

### API Reference

#### ProcessManager Methods

- `async start_process(config: ProcessConfig) -> asyncio.subprocess.Process`
  - Start a new process asynchronously
  - Returns the created subprocess object

- `async stop_process(pid: int, force: bool = False) -> bool`
  - Stop a running process gracefully or forcefully
  - Returns True if process was stopped successfully

- `async stop_all_processes(force: bool = False) -> None`
  - Stop all running processes
  - Can be graceful or forceful

- `async get_process_status(pid: int) -> Optional[Dict[str, Any]]`
  - Get detailed status information for a specific process
  - Returns None if process is not managed

- `async list_processes() -> List[Dict[str, Any]]`
  - Get list of all managed processes with their status

- `async wait_for_process(pid: int, timeout: Optional[float] = None) -> Optional[int]`
  - Wait for a process to complete
  - Returns exit code or None if timeout

- `async update_activity(pid: int) -> None`
  - Update activity timestamp for a process

- `async get_stats() -> Dict[str, Any]`
  - Get overall statistics about managed processes

- `async cleanup_finished_processes() -> int`
  - Remove finished processes from tracking
  - Returns count of cleaned processes

- `async shutdown() -> None`
  - Shutdown the process manager and stop all processes

## ProcessWatchdog

The `ProcessWatchdog` provides automated monitoring and termination of hanging processes with configurable thresholds and activity tracking.

### Monitoring Features

- **Activity Tracking**: Monitors process activity through callbacks or timestamps
- **Hang Detection**: Identifies processes that haven't been active for configured timeout periods
- **Automatic Termination**: Can automatically kill hanging processes based on policy
- **Configurable Thresholds**: Separate thresholds for warning, timeout, and force kill

### Configuration Options

```python
@dataclass
class WatchdogConfig:
    check_interval: float = 1.0      # How often to check processes (seconds)
    process_timeout: float = 30.0    # Time before process is considered hanging (seconds)
    extra_buffer: float = 5.0        # Extra time before auto-kill (seconds)
    max_hang_time: float = 60.0      # Maximum time before force kill (seconds)
    auto_kill: bool = True          # Whether to automatically kill hanging processes
```

### Usage Examples

#### Basic Watchdog Usage

```python
from mcp_fuzzer.fuzz_engine.runtime.watchdog import ProcessWatchdog, WatchdogConfig

async def basic_watchdog_usage():
    # Configure watchdog
    config = WatchdogConfig(
        check_interval=2.0,
        process_timeout=30.0,
        auto_kill=True
    )

    watchdog = ProcessWatchdog(config)

    # Start monitoring
    await watchdog.start()

    # Register a process for monitoring
    process = await asyncio.create_subprocess_exec("python", "test_server.py")
    await watchdog.register_process(
        process.pid,
        process,
        None,  # No activity callback
        "test_server"
    )

    # Let it run for a while
    await asyncio.sleep(10)

    # Stop monitoring
    await watchdog.stop()
```

#### Watchdog with Activity Callbacks

```python
import time

async def watchdog_with_activity():
    config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=10.0,
        auto_kill=True
    )

    watchdog = ProcessWatchdog(config)
    await watchdog.start()

    # Activity callback that simulates periodic activity
    last_activity = time.time()

    def activity_callback():
        nonlocal last_activity
        # Simulate activity every 5 seconds
        if time.time() - last_activity > 5:
            last_activity = time.time()
        return last_activity

    process = await asyncio.create_subprocess_exec("python", "server.py")
    await watchdog.register_process(
        process.pid,
        process,
        activity_callback,
        "server"
    )

    # Let it run
    await asyncio.sleep(20)

    await watchdog.stop()
```

#### Context Manager Usage

```python
async def watchdog_context_manager():
    config = WatchdogConfig(auto_kill=True)

    async with ProcessWatchdog(config) as watchdog:
        process = await asyncio.create_subprocess_exec("python", "server.py")
        await watchdog.register_process(
            process.pid,
            process,
            None,
            "server"
        )

        # Watchdog automatically starts and stops
        await asyncio.sleep(10)
```

### API Reference

#### ProcessWatchdog Methods

- `async start() -> None`
  - Start the watchdog monitoring loop

- `async stop() -> None`
  - Stop the watchdog monitoring loop

- `async register_process(pid: int, process: Any, activity_callback: Optional[Callable[[], float]], name: str) -> None`
  - Register a process for monitoring
  - Activity callback should return timestamp of last activity

- `async unregister_process(pid: int) -> None`
  - Unregister a process from monitoring

- `async update_activity(pid: int) -> None`
  - Update activity timestamp for a process

- `async is_process_registered(pid: int) -> bool`
  - Check if a process is registered for monitoring

- `async get_stats() -> dict`
  - Get statistics about monitored processes

## AsyncFuzzExecutor

The `AsyncFuzzExecutor` provides controlled concurrency and robust error handling for fuzzing operations with configurable timeouts and retry mechanisms.

### Concurrency Control

- **Bounded Concurrency**: Uses semaphore to limit concurrent operations
- **Task Tracking**: Maintains set of running tasks for proper shutdown
- **Batch Operations**: Execute multiple operations concurrently with result collection

### Error Handling

- **Timeout Management**: Configurable timeouts for individual operations
- **Retry Logic**: Exponential backoff retry mechanism for failed operations
- **Exception Collection**: Collects and categorizes errors from batch operations

### Configuration Options

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

### Usage Examples

#### Basic Executor Usage

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def basic_executor_usage():
    executor = AsyncFuzzExecutor(
        max_concurrency=3,
        timeout=10.0,
        retry_count=2
    )

    # Execute a single operation
    async def sample_operation():
        await asyncio.sleep(1)
        return "success"

    result = await executor.execute(sample_operation)
    print(f"Result: {result}")

    # Shutdown executor
    await executor.shutdown()
```

#### Executor with Retry Logic

```python
async def executor_with_retry():
    executor = AsyncFuzzExecutor(
        max_concurrency=2,
        timeout=5.0,
        retry_count=3,
        retry_delay=0.5
    )

    # Operation that might fail
    async def unreliable_operation():
        if random.random() < 0.7:  # 70% chance of failure
            raise Exception("Random failure")
        return "success"

    try:
        result = await executor.execute_with_retry(unreliable_operation)
        print(f"Result after retries: {result}")
    except Exception as e:
        print(f"All retries failed: {e}")

    await executor.shutdown()
```

#### Batch Operations

```python
async def batch_operations():
    executor = AsyncFuzzExecutor(max_concurrency=5)

    # Define multiple operations
    operations = []
    for i in range(10):
        async def operation(x=i):
            await asyncio.sleep(0.1)
            return f"result_{x}"

        operations.append((operation, [], {}))

    # Execute batch
    results = await executor.execute_batch(
        operations,
        collect_results=True,
        collect_errors=True
    )

    print(f"Successful results: {len(results['results'])}")
    print(f"Errors: {len(results['errors'])}")

    await executor.shutdown()
```

#### Custom Timeout and Concurrency

```python
async def custom_timeout_concurrency():
    executor = AsyncFuzzExecutor(
        max_concurrency=10,
        timeout=60.0
    )

    # Operation with custom timeout
    async def long_operation():
        await asyncio.sleep(2)
        return "long_result"

    # Execute with custom timeout
    result = await executor.execute(long_operation, timeout=120.0)
    print(f"Long operation result: {result}")

    await executor.shutdown()
```

### API Reference

#### AsyncFuzzExecutor Methods

- `async execute(operation: Callable[..., Awaitable[Any]], *args, timeout: Optional[float] = None, **kwargs) -> Any`
  - Execute a single operation with timeout and error handling
  - Returns result of the operation

- `async execute_with_retry(operation: Callable[..., Awaitable[Any]], *args, retry_count: Optional[int] = None, retry_delay: Optional[float] = None, **kwargs) -> Any`
  - Execute an operation with retries on failure
  - Uses exponential backoff for retry delays

- `async execute_batch(operations: List[Tuple[Callable[..., Awaitable[Any]], List, Dict]], collect_results: bool = True, collect_errors: bool = True) -> Dict[str, List]`
  - Execute a batch of operations concurrently with bounded concurrency
  - Returns dictionary with 'results' and 'errors' lists

- `async shutdown(timeout: float = 5.0) -> None`
  - Shutdown the executor, waiting for running tasks to complete
  - Cancels outstanding tasks if timeout is exceeded

## Integration Examples

### Complete Runtime Management Example

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig
from mcp_fuzzer.fuzz_engine.runtime.watchdog import ProcessWatchdog, WatchdogConfig
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor

async def complete_runtime_example():
    # Configure watchdog
    watchdog_config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=30.0,
        auto_kill=True
    )

    # Create runtime components
    manager = ProcessManager(watchdog_config)
    executor = AsyncFuzzExecutor(max_concurrency=3)

    try:
        # Start a test server
        server_config = ProcessConfig(
            command=["python", "test_server.py"],
            name="test_server",
            timeout=60.0
        )
        server_process = await manager.start_process(server_config)

        # Define fuzzing operations
        async def fuzz_operation():
            # Simulate fuzzing operation
            await asyncio.sleep(0.1)
            return {"status": "success", "timestamp": time.time()}

        # Execute fuzzing operations
        operations = [(fuzz_operation, [], {}) for _ in range(20)]
        results = await executor.execute_batch(operations)

        print(f"Fuzzing completed: {len(results['results'])} successful, {len(results['errors'])} errors")

        # Get process statistics
        stats = await manager.get_stats()
        print(f"Process statistics: {stats}")

    finally:
        # Cleanup
        await manager.shutdown()
        await executor.shutdown()

# Run the example
asyncio.run(complete_runtime_example())
```

### Transport Integration Example

```python
from mcp_fuzzer.transport.stdio import StdioTransport
from mcp_fuzzer.fuzz_engine.runtime.manager import ProcessManager, ProcessConfig

class ManagedStdioTransport(StdioTransport):
    def __init__(self, endpoint: str, manager: ProcessManager):
        super().__init__(endpoint)
        self.manager = manager
        self.process = None

    async def _start_process(self):
        """Start the managed process."""
        config = ProcessConfig(
            command=self.endpoint.split(),
            name="stdio_server",
            timeout=30.0
        )
        self.process = await self.manager.start_process(config)
        return self.process

    async def _stop_process(self):
        """Stop the managed process."""
        if self.process:
            await self.manager.stop_process(self.process.pid)
            self.process = None

# Usage
async def managed_transport_example():
    manager = ProcessManager()
    transport = ManagedStdioTransport("python test_server.py", manager)

    try:
        await transport.connect()
        # Use transport for fuzzing
        tools = await transport.get_tools()
        print(f"Available tools: {[tool['name'] for tool in tools]}")
    finally:
        await transport.disconnect()
        await manager.shutdown()
```

## Troubleshooting

### Common Issues

#### Process Not Starting

**Symptoms**: Process fails to start or immediately exits
**Solutions**:
- Check command path and arguments
- Verify working directory exists
- Check environment variables
- Review process logs for error messages

#### Process Hanging

**Symptoms**: Process appears to hang and doesn't respond
**Solutions**:
- Check watchdog configuration and timeout settings
- Verify activity callbacks are working correctly
- Review process logs for deadlocks or infinite loops
- Consider increasing timeout values

#### High Resource Usage

**Symptoms**: High CPU or memory usage during fuzzing
**Solutions**:
- Reduce `max_concurrency` in AsyncFuzzExecutor
- Increase `check_interval` in ProcessWatchdog
- Implement proper cleanup in activity callbacks
- Monitor process resource usage

#### Signal Handling Issues

**Symptoms**: Processes not terminating properly
**Solutions**:
- Check if process handles SIGTERM correctly
- Verify process group signaling on POSIX systems
- Consider using force kill for unresponsive processes
- Review process cleanup code

### Debug Configuration

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Configure watchdog with debug settings
debug_config = WatchdogConfig(
    check_interval=0.5,      # More frequent checks
    process_timeout=10.0,     # Shorter timeout for testing
    auto_kill=False          # Disable auto-kill for debugging
)

# Configure executor with debug settings
debug_executor = AsyncFuzzExecutor(
    max_concurrency=1,       # Single operation for debugging
    timeout=5.0,             # Shorter timeout
    retry_count=0            # No retries for debugging
)
```

### Performance Tuning

#### Optimizing Concurrency

```python
# For CPU-bound operations
cpu_executor = AsyncFuzzExecutor(max_concurrency=os.cpu_count())

# For I/O-bound operations
io_executor = AsyncFuzzExecutor(max_concurrency=os.cpu_count() * 2)

# For network operations
network_executor = AsyncFuzzExecutor(max_concurrency=10)
```

#### Optimizing Watchdog Performance

```python
# For high-frequency monitoring
fast_watchdog = WatchdogConfig(
    check_interval=0.1,
    process_timeout=5.0,
    auto_kill=True
)

# For low-frequency monitoring
slow_watchdog = WatchdogConfig(
    check_interval=5.0,
    process_timeout=60.0,
    auto_kill=True
)
```

This comprehensive runtime management system provides the foundation for robust, scalable fuzzing operations with proper process lifecycle management and error handling.
