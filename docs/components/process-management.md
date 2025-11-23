# Async Process Management System

The Process Management system provides comprehensive process lifecycle management with automatic watchdog monitoring, cross-platform support, and fully asynchronous interfaces. All operations are non-blocking and implemented using Python's asyncio framework.

## Overview

The system consists of three main components:

1. **ProcessWatchdog** - Monitors processes for hanging behavior and automatically kills them
2. **ProcessManager** - Fully asynchronous interface for process management with watchdog integration
3. **AsyncFuzzExecutor** - Provides controlled concurrency for executing asynchronous operations

## Architecture

```text
ProcessWatchdog (Core monitoring)
    |
ProcessManager (Fully async interface)
    |
AsyncFuzzExecutor (Controlled concurrency)
```

## Components

### AsyncFuzzExecutor

Provides controlled concurrency for executing asynchronous operations with timeout handling and retry mechanisms.

#### Configuring Concurrency

The executor's concurrency can be configured in several ways:

1. **Direct instantiation**:
   ```python
   executor = AsyncFuzzExecutor(max_concurrency=10)
   ```

2. **Via UnifiedMCPFuzzerClient**:
   ```python
   client = UnifiedMCPFuzzerClient(
       transport,
       max_concurrency=10  # Controls concurrency for both tool and protocol fuzzers
   )
   ```

3. **Future CLI integration**:
   ```bash
   # Planned feature - not yet implemented
   python -m mcp_fuzzer run --max-concurrency=10
   ```

```python
from mcp_fuzzer.fuzz_engine.executor import AsyncFuzzExecutor
import asyncio

async def main():
    # Create executor with concurrency control
    executor = AsyncFuzzExecutor(
        max_concurrency=5  # Maximum concurrent operations
    )

    try:
        # Define an async operation
        async def my_operation(value):
            await asyncio.sleep(0.1)  # Simulate work
            return value * 2

        # Execute batch operations concurrently
        operations = [
            (my_operation, [5], {}),
            (my_operation, [10], {}),
            (my_operation, [15], {})
        ]

        batch_results = await executor.execute_batch(operations)
        print(f"Batch results: {batch_results['results']}")

    finally:
        # Shutdown the executor
        await executor.shutdown()

asyncio.run(main())
```

### ProcessWatchdog

The core watchdog system that monitors processes for hanging behavior.

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessWatchdog, WatchdogConfig
import asyncio
import asyncio.subprocess as asp

async def main():
    # Custom configuration
    config = WatchdogConfig(
        check_interval=1.0,      # Check every second
        process_timeout=30.0,    # Process timeout after 30 seconds
        extra_buffer=5.0,        # Extra 5 seconds before killing
        max_hang_time=60.0,      # Force kill after 60 seconds
        auto_kill=True,          # Automatically kill hanging processes
    )

    watchdog = ProcessWatchdog(config)
    await watchdog.start()

    # Launch a subprocess to register
    process = await asp.create_subprocess_exec("python", "-c", "import time; time.sleep(60)")

    # Register a process for monitoring
    await watchdog.register_process(
        pid=process.pid,
        process=process,
        activity_callback=None,
        name="my_process",
    )

    # Some time later...
    await watchdog.stop()

asyncio.run(main())
```

### ProcessManager

Fully asynchronous process management interface that coordinates with the watchdog system.

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig
import asyncio

async def main():
    # Default wiring via factory (watchdog, registry, signals, lifecycle, monitor)
    manager = ProcessManager.create_with_config()

    # Start a process
    config = ProcessConfig(
        command=["python", "script.py"],
        cwd="/path/to/script",
        env={"PYTHONPATH": "/custom/path"},
        timeout=60.0,
        name="python_script"
    )

    process = await manager.start_process(config)
    print(f"Process started with PID: {process.pid}")

    # Wait for completion
    exit_code = await manager.wait_for_process(process.pid, timeout=120.0)

    # Get statistics
    stats = await manager.get_stats()
    print(f"Managed processes: {stats}")

    # Cleanup
    await manager.shutdown()

asyncio.run(main())
```

## Configuration

### WatchdogConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `check_interval` | 1.0 | How often to check processes (seconds) |
| `process_timeout` | 30.0 | Process timeout threshold (seconds) |
| `extra_buffer` | 5.0 | Extra buffer before killing (seconds) |
| `max_hang_time` | 60.0 | Maximum time a process can hang (seconds) |
| `auto_kill` | True | Whether to automatically kill hanging processes |

### ProcessConfig

| Parameter | Default | Description |
|-----------|---------|-------------|
| `command` | Required | Command and arguments as list |
| `cwd` | None | Working directory for the process |
| `env` | None | Environment variables |
| `timeout` | 30.0 | Process timeout (seconds) |
| `auto_kill` | True | Whether to automatically kill on timeout |
| `name` | "unknown" | Human-readable process name |
| `activity_callback` | None | Function returning last activity timestamp |

## Features

### Automatic Process Monitoring

- **Hanging Detection**: Automatically detects when processes stop responding
- **Timeout Management**: Configurable timeouts for different process types
- **Graceful Shutdown**: Attempts graceful termination before force killing
- **Cross-platform**: Works on Windows, Linux and macOS
- **Awaitable Activity Callbacks**: Support for async activity tracking functions

### Process Lifecycle Management

- **Start/Stop**: Easy asynchronous process starting and stopping
- **Status Tracking**: Monitor process status and health with async methods
- **Statistics**: Get comprehensive statistics about managed processes
- **Cleanup**: Automatic cleanup of finished processes
- **Process Groups**: Enhanced control through proper process group management

### Signal Handling

- **Timeout Signals**: Send SIGTERM (Unix). On Windows, use CTRL_BREAK_EVENT for graceful shutdown (requires CREATE_NEW_PROCESS_GROUP).
- **Force Signals**: Send SIGKILL (Unix). On Windows, use `process.kill()` (maps to TerminateProcess; no SIGKILL).
- **Interrupt Signals**: Send SIGINT (Unix) or CTRL_BREAK_EVENT (Windows) for user interruption (requires CREATE_NEW_PROCESS_GROUP).

Note: To deliver CTRL_BREAK_EVENT on Windows, the child must be started in its own process group and the console must be attached.

- **Bulk Operations**: Send signals to all processes at once

### Async Support

- **Fully Asynchronous**: All operations are non-blocking
- **Modern Asyncio**: Uses modern asyncio patterns and asyncio.subprocess
- **Event Loop Integration**: Integrates with existing async event loops
- **Awaitable Callbacks**: Support for both synchronous and asynchronous activity callbacks
- **Cross-Platform Async**: Consistent async behavior across Windows and Unix-like systems

### Safety Features

- **Resource Cleanup**: Automatic cleanup on shutdown
- **Error Handling**: Comprehensive error handling and logging
- **Process Isolation**: Processes are properly isolated using process groups and async-aware process management
- **Memory Management**: Efficient memory usage with proper cleanup

## Usage Examples

### Basic Process Management

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

async def main():
    # Create manager
    manager = ProcessManager.create_with_config()

    try:
        # Start a long-running process
        config = ProcessConfig(
            command=["python", "long_running_script.py"],
            name="long_script",
            timeout=300.0  # 5 minutes
        )

        process = await manager.start_process(config)
        print(f"Started process: {process.pid}")

        # Monitor status
        while True:
            status = await manager.get_process_status(process.pid)
            if status is None or status['status'] == 'finished':
                print(f"Process finished with exit code: {status and status.get('exit_code')}")
                break
            await asyncio.sleep(1)

    finally:
        await manager.shutdown()

asyncio.run(main())
```

### Multiple Process Management

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

async def run_multiple_processes():
    manager = ProcessManager.create_with_config()

    try:
        # Start multiple processes concurrently
        configs = []
        for i in range(3):
            configs.append(ProcessConfig(
                command=["python", f"worker_{i}.py"],
                name=f"worker_{i}"
            ))

        # Start all processes concurrently
        tasks = [manager.start_process(config) for config in configs]
        processes = await asyncio.gather(*tasks)

        # Wait for all to complete
        wait_tasks = [manager.wait_for_process(process.pid) for process in processes]
        results = await asyncio.gather(*wait_tasks)
        print(f"All processes completed with exit codes: {results}")

    finally:
        await manager.shutdown()

asyncio.run(run_multiple_processes())
```

### Custom Activity Monitoring

```python
import asyncio
import time
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

class CustomProcess:
    def __init__(self):
        self.last_activity = time.time()
        self.activity_count = 0

    def do_work(self):
        """Simulate some work."""
        self.last_activity = time.time()
        self.activity_count += 1

    def get_activity_timestamp(self):
        """Callback for watchdog to check activity."""
        return self.last_activity

async def main():
    # Create process manager
    manager = ProcessManager.create_with_config()

    # Create custom process
    custom_proc = CustomProcess()

    try:
        # Start monitoring with activity callback
        config = ProcessConfig(
            command=["python", "monitored_script.py"],
            name="monitored_script",
            activity_callback=custom_proc.get_activity_timestamp
        )

        process = await manager.start_process(config)

        # Simulate work
        for _ in range(10):
            custom_proc.do_work()
            await asyncio.sleep(1)

            # Update the activity timestamp in the watchdog
            await manager.update_activity(process.pid)

    finally:
        await manager.shutdown()

asyncio.run(main())
```

### Signal Handling

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

async def main():
    manager = ProcessManager.create_with_config()

    try:
        # Start a long-running process
        config = ProcessConfig(command=["python", "long_script.py"], name="long_script")
        process = await manager.start_process(config)

        # Send timeout signal (SIGTERM) for graceful shutdown
        success = await manager.send_timeout_signal(process.pid, "timeout")
        if success:
            print("Timeout signal sent successfully")

        # Wait a bit for graceful shutdown
        await asyncio.sleep(5)

        # If still running, send force signal (SIGKILL)
        status = await manager.get_process_status(process.pid)
        if status and status.get('status') == 'running':
            await manager.send_timeout_signal(process.pid, "force")
            print("Force signal sent")

        # Send signals to all processes
        results = await manager.send_timeout_signal_to_all("timeout")
        print(f"Signal results: {results}")

    finally:
        await manager.shutdown()

asyncio.run(main())
```

## Best Practices

1. **Always Cleanup**: Use try/finally blocks to ensure proper cleanup
2. **Configure Timeouts**: Set appropriate timeouts for your use case
3. **Monitor Resources**: Regularly check process statistics
4. **Handle Errors**: Implement proper error handling for process failures
5. **Use Async with Await**: Always await async methods
6. **Batch Operations**: Use asyncio.gather for concurrent operations

## Troubleshooting

### Common Issues

1. **Processes Not Being Killed**: Check watchdog configuration and permissions
2. **High CPU Usage**: Adjust check_interval to reduce monitoring overhead
3. **Memory Leaks**: Ensure proper cleanup with shutdown() methods
4. **Permission Errors**: Check process permissions and user privileges

### Debugging

Enable debug logging to see detailed watchdog activity:

```python
import logging
logging.getLogger('mcp_fuzzer.fuzz_engine.runtime').setLevel(logging.DEBUG)
```

### Performance Tuning

- **check_interval**: Lower values provide faster response but higher CPU usage
- **process_timeout**: Set based on expected process behavior

## Integration

The Process Management system integrates seamlessly with the MCP Fuzzer architecture:

- **Transport Layer**: Can manage transport processes (HTTP, SSE, stdio)
- **Fuzzer Components**: Monitor fuzzer processes for hanging
- **Safety System**: Integrate with safety monitoring and blocking
- **CLI Interface**: Command-line tools for process management

## API Reference

For complete API documentation, see the individual module docstrings:

- `mcp_fuzzer.fuzz_engine.runtime.watchdog`
- `mcp_fuzzer.fuzz_engine.runtime.manager`
- `mcp_fuzzer.fuzz_engine.executor`
