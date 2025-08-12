# Process Management System

The Process Management system provides comprehensive process lifecycle management with automatic watchdog monitoring, cross-platform support, and both synchronous and asynchronous interfaces.

## Overview

The system consists of three main components:

1. **ProcessWatchdog** - Monitors processes for hanging behavior and automatically kills them
2. **ProcessManager** - High-level interface for process management with watchdog integration
3. **AsyncProcessWrapper** - Async interfaces for process management operations

## Architecture

```
ProcessWatchdog (Core monitoring)
    ↓
ProcessManager (Synchronous interface)
    ↓
AsyncProcessWrapper (Asynchronous interface)
    ↓
AsyncProcessGroup (Group management)
```

## Components

### ProcessWatchdog

The core watchdog system that monitors processes for hanging behavior.

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessWatchdog, WatchdogConfig

# Custom configuration
config = WatchdogConfig(
    check_interval=1.0,      # Check every second
    process_timeout=30.0,    # Process timeout after 30 seconds
    extra_buffer=5.0,        # Extra 5 seconds before killing
    max_hang_time=60.0,      # Force kill after 60 seconds
    auto_kill=True,          # Automatically kill hanging processes
    log_level="WARNING"
)

watchdog = ProcessWatchdog(config)
watchdog.start()

# Register a process for monitoring
watchdog.register_process(pid, process, name="my_process")
```

### ProcessManager

High-level process management interface that coordinates with the watchdog system.

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

manager = ProcessManager()

# Start a process
config = ProcessConfig(
    command=["python", "script.py"],
    cwd="/path/to/script",
    env={"PYTHONPATH": "/custom/path"},
    timeout=60.0,
    name="python_script"
)

process = manager.start_process(config)
print(f"Process started with PID: {process.pid}")

# Wait for completion
exit_code = manager.wait_for_process(process.pid, timeout=120.0)

# Get statistics
stats = manager.get_stats()
print(f"Managed processes: {stats}")

# Cleanup
manager.shutdown()
```

### AsyncProcessWrapper

Async wrapper around ProcessManager for use in async contexts.

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import AsyncProcessWrapper, ProcessConfig

async def main():
    wrapper = AsyncProcessWrapper()

    # Start processes asynchronously
    config1 = ProcessConfig(command=["sleep", "5"], name="sleep1")
    config2 = ProcessConfig(command=["echo", "hello"], name="echo1")

    process1 = await wrapper.start_process(config1)
    process2 = await wrapper.start_process(config2)

    # Wait for all to complete
    await wrapper.wait_for_process(process1.pid)
    await wrapper.wait_for_process(process2.pid)

    # Cleanup
    await wrapper.shutdown()

asyncio.run(main())
```

### AsyncProcessGroup

Manages groups of related processes that should be started, stopped, or monitored together.

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import AsyncProcessGroup, ProcessConfig

async def main():
    group = AsyncProcessGroup()

    # Add multiple processes
    await group.add_process("web_server", ProcessConfig(
        command=["python", "web_server.py"],
        name="web_server"
    ))

    await group.add_process("database", ProcessConfig(
        command=["python", "database.py"],
        name="database"
    ))

    # Start all processes
    started = await group.start_all()
    print(f"Started {len(started)} processes")

    # Wait for all to complete
    results = await group.wait_for_all()
    print(f"Results: {results}")

    # Cleanup
    await group.shutdown()

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
| `log_level` | "WARNING" | Logging level for watchdog events |

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
- **Cross-platform**: Works on Windows, Linux, and macOS

### Process Lifecycle Management

- **Start/Stop**: Easy process starting and stopping
- **Status Tracking**: Monitor process status and health
- **Statistics**: Get comprehensive statistics about managed processes
- **Cleanup**: Automatic cleanup of finished processes

### Signal Handling

- **Timeout Signals**: Send SIGTERM for graceful shutdown
- **Force Signals**: Send SIGKILL for immediate termination
- **Interrupt Signals**: Send SIGINT for user interruption
- **Bulk Operations**: Send signals to all processes at once

### Async Support

- **Non-blocking**: All operations can be performed asynchronously
- **Thread Pool**: Uses thread pool for CPU-bound operations
- **Event Loop Integration**: Integrates with existing async event loops
- **Group Management**: Manage multiple related processes together

### Safety Features

- **Resource Cleanup**: Automatic cleanup on shutdown
- **Error Handling**: Comprehensive error handling and logging
- **Process Isolation**: Processes are properly isolated and managed
- **Memory Management**: Efficient memory usage with proper cleanup

## Usage Examples

### Basic Process Management

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

# Create manager
manager = ProcessManager()

try:
    # Start a long-running process
    config = ProcessConfig(
        command=["python", "long_running_script.py"],
        name="long_script",
        timeout=300.0  # 5 minutes
    )

    process = manager.start_process(config)
    print(f"Started process: {process.pid}")

    # Monitor status
    while True:
        status = manager.get_process_status(process.pid)
        if status['status'] == 'finished':
            print(f"Process finished with exit code: {status.get('exit_code')}")
            break
        time.sleep(1)

finally:
    manager.shutdown()
```

### Async Process Management

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import AsyncProcessWrapper, ProcessConfig

async def run_multiple_processes():
    wrapper = AsyncProcessWrapper()

    try:
        # Start multiple processes concurrently
        tasks = []
        for i in range(3):
            config = ProcessConfig(
                command=["python", f"worker_{i}.py"],
                name=f"worker_{i}"
            )
            task = wrapper.start_process(config)
            tasks.append(task)

        # Wait for all to start
        processes = await asyncio.gather(*tasks)

        # Wait for all to complete
        for process in processes:
            await wrapper.wait_for_process(process.pid)

    finally:
        await wrapper.shutdown()

asyncio.run(run_multiple_processes())
```

### Custom Activity Monitoring

```python
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
        time.sleep(0.1)

    def get_activity_timestamp(self):
        """Callback for watchdog to check activity."""
        return self.last_activity

# Create process manager
manager = ProcessManager()

# Create custom process
custom_proc = CustomProcess()

# Start monitoring with activity callback
config = ProcessConfig(
    command=["python", "monitored_script.py"],
    name="monitored_script",
    activity_callback=custom_proc.get_activity_timestamp
)

process = manager.start_process(config)

# Simulate work
for _ in range(10):
    custom_proc.do_work()
    time.sleep(1)

manager.shutdown()
```

### Signal Handling

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessManager, ProcessConfig

manager = ProcessManager()

# Start a long-running process
config = ProcessConfig(command=["python", "long_script.py"], name="long_script")
process = manager.start_process(config)

# Send timeout signal (SIGTERM) for graceful shutdown
success = manager.send_timeout_signal(process.pid, "timeout")
if success:
    print("Timeout signal sent successfully")

# Wait a bit for graceful shutdown
time.sleep(5)

# If still running, send force signal (SIGKILL)
status = manager.get_process_status(process.pid)
if status and status.get('status') == 'running':
    manager.send_timeout_signal(process.pid, "force")
    print("Force signal sent")

# Send signals to all processes
results = manager.send_timeout_signal_to_all("timeout")
print(f"Signal results: {results}")

manager.shutdown()
```

### Async Signal Handling

```python
import asyncio
from mcp_fuzzer.fuzz_engine.runtime import AsyncProcessWrapper, ProcessConfig

async def main():
    wrapper = AsyncProcessWrapper()

    # Start a process
    config = ProcessConfig(command=["python", "script.py"], name="test_script")
    process = await wrapper.start_process(config)

    # Send interrupt signal (SIGINT)
    success = await wrapper.send_timeout_signal(process.pid, "interrupt")
    print(f"Interrupt signal sent: {success}")

    # Wait for completion
    exit_code = await wrapper.wait_for_process(process.pid)
    print(f"Process completed with exit code: {exit_code}")

    await wrapper.shutdown()

asyncio.run(main())
```

## Best Practices

1. **Always Cleanup**: Use try/finally blocks to ensure proper cleanup
2. **Configure Timeouts**: Set appropriate timeouts for your use case
3. **Monitor Resources**: Regularly check process statistics
4. **Handle Errors**: Implement proper error handling for process failures
5. **Use Async**: Prefer async interfaces for better performance
6. **Group Related Processes**: Use AsyncProcessGroup for related processes

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
- **max_workers**: Adjust thread pool size for async operations

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
- `mcp_fuzzer.fuzz_engine.runtime.wrapper`
