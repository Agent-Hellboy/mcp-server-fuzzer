# Process management

MCP Server Fuzzer supervises local processes used by stdio transports and
other runtime integrations. The runtime layer is asynchronous and separates
process state, watchdog policy, and signal delivery so each concern can be
tested independently.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| `ProcessManager` | Starts, stops, waits for, and tracks managed subprocesses. |
| `ProcessRegistry` | Owns the current process records shared by the manager and watchdog. |
| `ProcessWatchdog` | Detects stale activity and applies the configured termination policy. |
| `SignalDispatcher` | Delivers graceful, force, and interrupt signals through the platform strategy. |
| `ProcessConfig` | Describes the command, environment, working directory, timeout, and activity callback. |
| `WatchdogConfig` | Sets check interval, timeout thresholds, buffering, and auto-kill behavior. |

The [`AsyncFuzzExecutor`](../architecture/async-executor.md) is a separate
concurrency primitive for fuzz operations. It is not a process supervisor and
is documented only on its architecture page.

## Runtime wiring

```text
ProcessConfig
     |
ProcessManager ---- ProcessRegistry ---- ProcessWatchdog
     |                                      |
     +------------ SignalDispatcher --------+
```

Use `ProcessManager.from_config(...)` for the standard runtime wiring. Pass
explicit dependencies to `ProcessManager` when tests or integrations need a
custom registry, signal strategy, or watchdog policy.

## Process lifecycle

| State | Meaning |
| --- | --- |
| Unregistered | The process is not tracked by the runtime registry. |
| Registered | An existing process has been added to the registry. |
| Running | The manager launched the process and recorded its start. |
| Stopping | A graceful or forced stop has been requested. |
| Stopped | The process exited or was terminated and its result was recorded. |
| Shutdown | The manager stopped all tracked processes and the watchdog. |

Observers can consume manager events such as `started`, `stopped`, `signal`,
`stopped_all`, and `shutdown`.

## Configuration

### `ProcessConfig`

| Field | Default | Description |
| --- | --- | --- |
| `command` | required | Executable and arguments as a list. |
| `cwd` | `None` | Working directory for the child process. |
| `env` | `None` | Environment mapping for the child process. |
| `timeout` | `30.0` | Process timeout in seconds. |
| `auto_kill` | `True` | Whether the watchdog may terminate a stale process. |
| `name` | `"unknown"` | Human-readable name for logs and events. |
| `activity_callback` | `None` | Sync or async callback returning the latest activity timestamp. |

### `WatchdogConfig`

| Field | Default | Description |
| --- | --- | --- |
| `check_interval` | `1.0` | Seconds between watchdog checks. |
| `process_timeout` | `30.0` | Inactivity threshold before a process is considered stale. |
| `extra_buffer` | `5.0` | Grace period before termination. |
| `max_hang_time` | `60.0` | Maximum allowed hang time. |
| `auto_kill` | `True` | Whether stale processes are terminated automatically. |

The CLI exposes these settings as `--watchdog-*`, `--process-max-concurrency`,
and `--process-retry-*` options. See the [CLI reference](../development/reference.md)
for defaults and the [process management guide](process-management-guide.md)
for operational choices.

## Safety and platform behavior

Process management is not a security boundary by itself. Run local targets in
a disposable workspace, use `--fs-root` and `--no-network` where appropriate,
and apply the safety system before starting an untrusted stdio server.

Signal behavior is platform-specific: Unix uses signals such as `SIGTERM`,
`SIGINT`, and `SIGKILL`; Windows uses the supported process-group and terminate
operations. A graceful stop may be followed by a force stop when the configured
maximum hang time is exceeded.

## Public API pointers

The implementation lives under `mcp_fuzzer.fuzz_engine.runtime`. The focused
guidance page covers startup, timeouts, activity updates, shutdown, and
troubleshooting. The API reference should be read alongside the source and
tests when building an integration.
