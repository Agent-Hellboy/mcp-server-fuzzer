# Process Management and Troubleshooting Guide

This guide provides comprehensive information on managing processes, configuring the watchdog system, and troubleshooting common issues in the MCP Server Fuzzer runtime management system.

## Process Management Best Practices

### Starting Processes

When starting processes with the ProcessManager, follow these best practices:
Use `ProcessManager.from_config(...)` for the default runtime wiring, or build your own dependencies and pass them to the `ProcessManager` constructor when you need custom registries, signal strategies, or watchdog settings.

#### 1. Use Descriptive Names

```python
config = ProcessConfig(
    command=["python", "test_server.py"],
    name="test_server",  # Clear, descriptive name
    timeout=60.0
)
```

#### 2. Set Appropriate Timeouts

```python
# For quick operations
config = ProcessConfig(
    command=["python", "quick_test.py"],
    timeout=10.0
)

# For long-running servers
config = ProcessConfig(
    command=["python", "production_server.py"],
    timeout=300.0
)
```

#### 3. Configure Working Directory

```python
config = ProcessConfig(
    command=["python", "server.py"],
    cwd="/path/to/server/directory",
    name="server"
)
```

#### 4. Set Environment Variables

```python
config = ProcessConfig(
    command=["python", "server.py"],
    env={
        "PYTHONPATH": "/custom/path",
        "LOG_LEVEL": "DEBUG",
        "PORT": "8080"
    },
    name="server"
)
```

### Process Monitoring

#### Activity Callbacks

Implement activity callbacks to provide accurate hang detection:

```python
import time

class ServerActivityTracker:
    def __init__(self):
        self.last_request_time = time.time()

    def update_request(self):
        self.last_request_time = time.time()

    def get_last_activity(self):
        return self.last_request_time

# Usage
tracker = ServerActivityTracker()
config = ProcessConfig(
    command=["python", "server.py"],
    name="server",
    activity_callback=tracker.get_last_activity
)
```

#### Manual Activity Updates

```python
# Update activity when you know the process is working
await manager.update_activity(process.pid)

# Or use a periodic updater
async def periodic_activity_update(manager, pid, interval=5.0):
    while True:
        await manager.update_activity(pid)
        await asyncio.sleep(interval)
```

### Process Lifecycle Management

#### Graceful Shutdown

```python
async def graceful_shutdown_example():
    manager = ProcessManager.from_config()

    # Start process
    config = ProcessConfig(command=["python", "server.py"], name="server")
    process = await manager.start_process(config)

    try:
        # Do work
        await asyncio.sleep(10)
    finally:
        # Always cleanup
        await manager.stop_process(process.pid)
        await manager.shutdown()
```

#### Force Kill When Needed

```python
# Try graceful first
success = await manager.stop_process(process.pid, force=False)
if not success:
    # Escalate to force kill
    await manager.stop_process(process.pid, force=True)
```

## Watchdog Configuration

### Basic Configuration

```python
from mcp_fuzzer.fuzz_engine.runtime import WatchdogConfig

# Conservative settings for production
production_config = WatchdogConfig(
    check_interval=5.0,      # Check every 5 seconds
    process_timeout=60.0,    # 1 minute timeout
    extra_buffer=10.0,       # 10 second buffer
    max_hang_time=300.0,     # 5 minutes max hang
    auto_kill=True
)

# Aggressive settings for testing
testing_config = WatchdogConfig(
    check_interval=1.0,      # Check every second
    process_timeout=10.0,    # 10 second timeout
    extra_buffer=2.0,        # 2 second buffer
    max_hang_time=30.0,      # 30 seconds max hang
    auto_kill=True
)
```

### Environment-Specific Configurations

#### Development Environment

```python
dev_config = WatchdogConfig(
    check_interval=2.0,
    process_timeout=30.0,
    extra_buffer=5.0,
    max_hang_time=120.0,
    auto_kill=False  # Disable auto-kill for debugging
)
```

#### CI/CD Environment

```python
ci_config = WatchdogConfig(
    check_interval=1.0,
    process_timeout=15.0,
    extra_buffer=3.0,
    max_hang_time=60.0,
    auto_kill=True
)
```

#### Production Environment

```python
prod_config = WatchdogConfig(
    check_interval=10.0,
    process_timeout=120.0,
    extra_buffer=30.0,
    max_hang_time=600.0,
    auto_kill=True
)
```

### Watchdog Integration Patterns

#### With ProcessManager

```python
async def managed_process_example():
    watchdog_config = WatchdogConfig(auto_kill=True)
    manager = ProcessManager.from_config(watchdog_config)

    # Processes are automatically registered with watchdog
    config = ProcessConfig(command=["python", "server.py"], name="server")
    process = await manager.start_process(config)

    # Watchdog monitors automatically
    await asyncio.sleep(60)

    await manager.shutdown()
```

#### Standalone Watchdog

```python
async def standalone_watchdog_example():
    watchdog = ProcessWatchdog(WatchdogConfig())

    # Start monitoring
    await watchdog.start()

    # Register existing process
    process = await asyncio.create_subprocess_exec("python", "server.py")
    await watchdog.register_process(
        process.pid,
        process,
        None,  # No activity callback
        "server"
    )

    # Monitor for a while
    await asyncio.sleep(30)

    await watchdog.stop()
```

## AsyncFuzzExecutor Best Practices

### Concurrency Configuration

#### CPU-Bound Operations

```python
import os

# Use CPU count for CPU-bound operations
cpu_executor = AsyncFuzzExecutor(
    max_concurrency=os.cpu_count()
)
```

#### I/O-Bound Operations

```python
# Use higher concurrency for I/O-bound operations
io_executor = AsyncFuzzExecutor(
    max_concurrency=os.cpu_count() * 2
)
```

#### Network Operations

```python
# Conservative concurrency for network operations
network_executor = AsyncFuzzExecutor(
    max_concurrency=10
)
```

### Error Handling Patterns

#### Batch Processing with Automatic Error Collection

```python
async def batch_processing_example():
    executor = AsyncFuzzExecutor(max_concurrency=5)

    # Define operations
    operations = [
        (operation1, [], {}),
        (operation2, [], {}),
        (operation3, [], {}),
    ]

    # Execute with error collection
    results = await executor.execute_batch(
        operations,
        collect_results=True,
        collect_errors=True
    )

    # Process results
    for result in results['results']:
        process_success(result)

    # Handle errors
    for error in results['errors']:
        logger.error(f"Operation failed: {error}")
```

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Process Not Starting

**Symptoms:**
- Process fails to start
- Immediate exit with error code
- "Process not found" errors

**Diagnosis:**
```python
# Check if command exists
import shutil
command_path = shutil.which("python")
if not command_path:
    print("Python not found in PATH")

# Check working directory
import os
if not os.path.exists(config.cwd):
    print(f"Working directory {config.cwd} does not exist")
```

**Solutions:**
- Verify command path and arguments
- Check working directory exists
- Verify environment variables
- Check file permissions
- Review process logs

#### 2. Process Hanging

**Symptoms:**
- Process appears to hang
- No response to requests
- Watchdog kills process

**Diagnosis:**
```python
# Check process status
status = await manager.get_process_status(pid)
print(f"Process status: {status}")

# Check watchdog stats
stats = await watchdog.get_stats()
print(f"Watchdog stats: {stats}")

# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Solutions:**
- Implement activity callbacks
- Increase timeout values
- Check for deadlocks in process code
- Review process resource usage
- Verify network connectivity

#### 3. High Resource Usage

**Symptoms:**
- High CPU usage
- High memory usage
- System slowdown

**Diagnosis:**
```python
# Monitor resource usage
import psutil

def monitor_resources(pid):
    process = psutil.Process(pid)
    cpu_percent = process.cpu_percent()
    memory_info = process.memory_info()
    print(f"CPU: {cpu_percent}%, Memory: {memory_info.rss / 1024 / 1024:.1f} MB")
```

**Solutions:**
- Reduce concurrency limits
- Increase check intervals
- Implement proper cleanup
- Monitor process resource usage
- Use process limits

#### 4. Signal Handling Issues

**Symptoms:**
- Processes not terminating
- Zombie processes
- Signal errors

**Diagnosis:**
```python
# Check process group
import os
try:
    pgid = os.getpgid(pid)
    print(f"Process group ID: {pgid}")
except OSError as e:
    print(f"Error getting process group: {e}")
```

**Solutions:**
- Verify process handles SIGTERM
- Check process group signaling
- Use force kill when needed
- Implement proper signal handlers
- Review process cleanup code

### Debug Configuration

#### Enable Debug Logging

```python
import logging

# Configure debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Enable specific logger
logger = logging.getLogger('mcp_fuzzer.fuzz_engine.runtime')
logger.setLevel(logging.DEBUG)
```

#### Debug Watchdog Configuration

```python
debug_config = WatchdogConfig(
    check_interval=0.5,      # More frequent checks
    process_timeout=5.0,     # Shorter timeout for testing
    auto_kill=False          # Disable auto-kill for debugging
)
```

#### Debug Executor Configuration

```python
debug_executor = AsyncFuzzExecutor(
    max_concurrency=1        # Single operation for debugging
)
```

### Performance Monitoring

#### Process Statistics

```python
async def monitor_processes(manager):
    while True:
        stats = await manager.get_stats()
        print(f"Process stats: {stats}")

        # List all processes
        processes = await manager.list_processes()
        for proc in processes:
            print(f"Process {proc['config'].name}: {proc['status']}")

        await asyncio.sleep(10)
```

#### Watchdog Statistics

```python
async def monitor_watchdog(watchdog):
    while True:
        stats = await watchdog.get_stats()
        print(f"Watchdog stats: {stats}")
        await asyncio.sleep(5)
```

#### Executor Statistics

```python
async def monitor_executor(executor):
    # Monitor running tasks
    running_count = len(executor._running_tasks)
    print(f"Running tasks: {running_count}")

    # Monitor semaphore
    semaphore_count = executor._semaphore._value
    print(f"Available semaphore slots: {semaphore_count}")
```

### Error Recovery Patterns

#### Graceful Degradation

```python
async def graceful_degradation_example():
    try:
        # Try high concurrency first
        executor = AsyncFuzzExecutor(max_concurrency=10)
        results = await executor.execute_batch(operations)
    except Exception as e:
        logger.warning(f"High concurrency failed: {e}")

        # Fall back to lower concurrency
        executor = AsyncFuzzExecutor(max_concurrency=3)
        results = await executor.execute_batch(operations)

    return results
```

#### Circuit Breaker Pattern

```python
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    async def call(self, operation):
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = await operation()
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"

            raise e
```

### Best Practices Summary

1. **Always use descriptive names** for processes
2. **Set appropriate timeouts** based on operation type
3. **Implement activity callbacks** for accurate hang detection
4. **Use graceful shutdown** with escalation to force kill
5. **Monitor resource usage** and adjust concurrency accordingly
6. **Enable debug logging** for troubleshooting
7. **Implement error recovery** patterns
8. **Clean up resources** properly in finally blocks
9. **Use environment-specific configurations** for different deployments
10. **Monitor process statistics** for performance optimization

This guide provides comprehensive information for managing processes effectively and troubleshooting common issues in the MCP Server Fuzzer runtime management system.
