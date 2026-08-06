# Runtime management

Runtime management is the boundary between the fuzzer and local processes used
by stdio transports. It combines process lifecycle control, watchdog policy,
signal delivery, and audit-safe cleanup.

## Choose the right page

| Need | Page |
| --- | --- |
| Understand process state, watchdog configuration, and platform signals | [Process management](process-management.md) |
| Start a target, tune timeouts, or troubleshoot cleanup | [Process management guide](process-management-guide.md) |
| Understand bounded async/sync fuzz operation execution | [Async executor](../architecture/async-executor.md) |
| Trace how executors connect to mutators and reporting | [Fuzz engine architecture](../architecture/fuzz-engine.md) |

## Runtime boundary

```text
CLI / audit workflow
        |
Transport bootstrap ---- ProcessManager ---- ProcessRegistry
        |                                      |
        +------------------------------ ProcessWatchdog
                                               |
                                      SignalDispatcher
```

`ProcessManager` owns lifecycle operations. `ProcessWatchdog` reads the shared
registry and applies configured hang policy. `AsyncFuzzExecutor` is deliberately
separate: it bounds concurrent fuzz operations and does not supervise child
processes.

## Audit guidance

For local MCP security research:

1. Use an isolated working directory and dedicated test credentials.
2. Set `--fs-root` when generated tool arguments may contain filesystem paths.
3. Set `--no-network` unless the target's network behavior is in scope.
4. Use bounded `--watchdog-*` settings and preserve timeout/crash artifacts.
5. Run cleanup in a `finally` path when embedding the runtime API.

Runtime supervision is an operational control, not proof that a target is safe.
Review runtime findings and server output as assessment evidence.

## Source and tests

The implementation is under `mcp_fuzzer.fuzz_engine.runtime`. The maintained
unit tests cover lifecycle transitions, watchdog scans, signals, registries,
and cleanup behavior. Update the focused pages above when the runtime contract
changes; do not add another copy of the executor API here.
