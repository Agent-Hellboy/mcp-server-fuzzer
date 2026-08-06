# Process management guide

Use this guide when an MCP audit starts a local stdio server or when a runtime
process hangs, exits unexpectedly, or needs cleanup. For the component model
and configuration contract, see [Process management](process-management.md).

## Start a managed process safely

Use a descriptive name, an explicit working directory, and a timeout that is
long enough for the target's normal startup and request cycle:

```python
from mcp_fuzzer.fuzz_engine.runtime import ProcessConfig, ProcessManager

manager = ProcessManager.from_config()
config = ProcessConfig(
    command=["python", "my_server.py"],
    cwd="/path/to/server",
    name="audit-stdio-server",
    timeout=60.0,
)
```

Always clean up the manager in a `finally` block:

```python
import asyncio


async def run_target():
    manager = ProcessManager.from_config()
    try:
        process = await manager.start_process(config)
        result = await manager.wait(process.pid)
        return result
    finally:
        await manager.shutdown()


asyncio.run(run_target())
```

For a CLI audit, the equivalent controls are:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --watchdog-process-timeout 60 \
  --output-dir reports
```

## Configure activity and timeouts

The watchdog needs a meaningful activity signal. If a managed integration can
observe request progress, expose the latest activity timestamp:

```python
import time


class Activity:
    def __init__(self):
        self.last_request = time.time()

    def update(self):
        self.last_request = time.time()

    def timestamp(self):
        return self.last_request


activity = Activity()
config = ProcessConfig(
    command=["python", "server.py"],
    name="server",
    timeout=120.0,
    activity_callback=activity.timestamp,
)
```

Choose values from the target's measured behavior. A short timeout can turn
normal startup or a slow test into a false hang; a long timeout delays cleanup
after a genuine failure. `check_interval`, `process_timeout`,
`extra_buffer`, and `max_hang_time` are independent controls.

## Stop and signal processes

Prefer a graceful stop first. Use a force stop only when the process does not
exit within the configured grace period. The runtime sends platform-appropriate
signals and records the transition for observers.

```python
stopped = await manager.stop_process(process.pid)
if not stopped:
    await manager.stop_process(process.pid, force=True)
```

Do not send signals to processes outside the manager's authorized registry.
Keep audit targets isolated so a cleanup failure cannot affect unrelated work.

## Troubleshooting

### The process does not start

- Verify the executable is available in the manager's environment.
- Use an absolute `cwd` and confirm the target files are readable.
- Check the command list: each argument must be a separate item.
- Inspect the CLI's startup error and the target's stderr output.

### The watchdog reports a hang

- Confirm the timeout reflects measured target behavior.
- Check whether the activity callback is updated during legitimate work.
- Re-run with `--log-level DEBUG` to inspect runtime and transport events.
- Preserve the crash or timeout artifacts before changing the configuration.

### Cleanup is incomplete

- Ensure `shutdown()` runs in `finally` even when the audit raises.
- Check whether the target created child processes that require process-group
  cleanup.
- Increase the graceful buffer only when the target needs it; do not disable
  automatic cleanup as a general workaround.

### Resource usage is high

- Lower `--process-max-concurrency` and `--max-concurrency`.
- Increase `--watchdog-check-interval` if supervision is too chatty.
- Keep fuzz run counts bounded while reproducing a finding.

## What this page does not cover

`AsyncFuzzExecutor` controls concurrent async/sync operations and is unrelated
to child-process lifecycle management. Read its [architecture and API
page](../architecture/async-executor.md) for `execute_batch`, Hypothesis
strategy execution, and executor shutdown.
