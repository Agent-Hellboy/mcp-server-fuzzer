# Safety Guide

The MCP Server Fuzzer ships with a layered safety stack that protects the host
machine while still allowing realistic fuzzing sessions. This guide explains the
available components, how they work, and how to configure them through the CLI
or programmatically.

## Safety Architecture

The safety subsystem lives under `mcp_fuzzer/safety_system` and is composed of:

- **SafetyFilter** (`safety.py`) – argument-level hooks plus optional filesystem
  path sanitization; includes `DangerDetector` helpers for custom blocking.
- **Filesystem Sandbox** (`filesystem/`) – `FilesystemSandbox` and
  `PathSanitizer` confine file paths to a safe root via `--fs-root` or
  `MCP_FUZZER_FS_ROOT`.
- **System Command Blocking** (`blocking/command_blocker.py`) – installs PATH
  shims (the `SystemCommandBlocker`) so dangerous commands and browser launches
  never leave the machine.
- **Network Policy Helpers** (`policy.py`) – normalize hosts and enforce
  `--no-network` / `--allow-host` rules inside transports.
- **Safety Reporter** (`reporting/`) – aggregates blocked operations and prints
  detailed reports with `--safety-report` or `--export-safety-data`.

The CLI enables argument-level safety hooks by default. System command blocking,
filesystem sandboxing, and reporting are opt-in controls layered on top.

## Argument-Level Hooks (`SafetyFilter`)

`SafetyFilter` is the default safety provider for tool fuzzing. It intentionally
passes URL/script/command payloads through so the server is tested with real
inputs. Protection happens at system boundaries instead:

- **System command blocking** (`--enable-safety-system`)
- **Filesystem sandboxing** (`--fs-root`)
- **Network policy controls** (`--no-network`, `--allow-host`)

When a sandbox root is set, filesystem paths are rewritten into safe equivalents
under that root. `DangerDetector` helpers are still available if you want to
implement stricter blocking in a custom safety provider.

```python
from mcp_fuzzer.safety_system.safety import SafetyFilter

filter = SafetyFilter()
filter.set_fs_root("/tmp/mcp_sandbox")

args = {"output_path": "/etc/passwd"}
sanitized = filter.sanitize_tool_arguments("file_tool", args)
# sanitized["output_path"] now points inside /tmp/mcp_sandbox
```

Filesystem arguments are sanitized automatically once a sandbox root is set
(either through the CLI or by calling `set_fs_root()` on the filter).

If you implement stricter blocking in a custom provider, you can use
`create_safe_mock_response()` to fabricate a consistent JSON-RPC error.

## Filesystem Sandbox

The sandbox forces all file paths to stay under a safe directory. It is powered
by `FilesystemSandbox` and the `PathSanitizer` heuristics discussed earlier.

- CLI flag: `--fs-root /tmp/mcp_fuzzer_safe`
- Environment variable: `MCP_FUZZER_FS_ROOT=/tmp/mcp_fuzzer_safe`
- Programmatic: `SafetyFilter().set_fs_root("/tmp/mcp")`

If you do not set `--fs-root` (or `MCP_FUZZER_FS_ROOT` in environments where it
is applied), the filesystem sandbox is not initialized and file paths are not
confined.

The sandbox rejects system directories (`/`, `/etc`, `/usr`, etc.), enforces
0700 permissions, and rewrites suspicious arguments (e.g., `../../etc/passwd`)
into safe equivalents under the sandbox root. When fuzzing tools need to write
files, point them to the sandbox path that SafetyFilter provides.

## System Command Blocking (`SystemCommandBlocker`)

Some MCP tools try to spawn browsers or perform OS-level actions. When
`--enable-safety-system` is set, the fuzzer instantiates
`mcp_fuzzer.safety_system.blocking.command_blocker.SystemCommandBlocker` and
adds a temporary directory to the front of `PATH`. That directory contains shim
executables for commands such as:

- Desktop launchers: `xdg-open`, `open`, `start`
- Browsers: `firefox`, `chrome`, `chromium`, `safari`, `edge`, `opera`, `brave`

Each shim logs the attempted command to a JSONL file and exits cleanly so the
fuzzing run continues without triggering the real application.

```python
from mcp_fuzzer.safety_system.blocking import (
    start_system_blocking,
    stop_system_blocking,
    get_blocked_operations,
)

start_system_blocking()
try:
    # Run fuzzing / external processes here
    ...
finally:
    operations = get_blocked_operations()
    stop_system_blocking()

for op in operations:
    print(f"Blocked: {op['command']} at {op['timestamp']}")
```

Use `--retry-with-safety-on-interrupt` to automatically retry a run with system
blocking if you cancel an unsafe run.

## CLI Safety Controls

| Flag | Description |
| --- | --- |
| `--enable-safety-system` | Activate PATH shims for browsers/launchers. |
| `--fs-root PATH` | Set the filesystem sandbox root (only applied when provided). |
| `--no-safety` | Disable argument-level safety hooks (not recommended). |
| `--safety-report` | Print the full safety report at the end of the session. |
| `--export-safety-data [FILE]` | Save safety data as JSON, optionally to a custom filename. |
| `--retry-with-safety-on-interrupt` | Re-run once with system blocking after Ctrl-C. |
| `--no-network` / `--allow-host HOST` | Restrict outbound HTTP targets. |

Example:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python test_server.py" \
  --enable-safety-system \
  --fs-root /tmp/mcp_sandbox \
  --safety-report \
  --export-safety-data blocked.json
```

## Environment Variables

Environment variables mirror the most common safety options:

```bash
export MCP_FUZZER_SAFETY_ENABLED=true   # Turn on SafetyFilter by default
export MCP_FUZZER_FS_ROOT=~/.mcp_fuzzer # Sandbox root for filesystem paths
```

When both CLI flags and environment variables are provided, CLI values win.

## Safety Reporting

When `--safety-report` is enabled, the `SafetyReporter` prints:

- SafetyFilter statistics (blocked operations count, risk assessment) if any.
- A table of blocked operations when custom SafetyFilter logic is used.
- System command blocker statistics (count and preview of attempts).

`--export-safety-data` writes the same structured data to disk so you can attach
it to a bug report or CI artifact. Standardized output artifacts (`output.types`
containing `safety_summary`) convey the same information in a machine-readable
format.

## Extending Detection and Sandbox Providers

You can customize detection patterns by passing explicit lists when constructing
`SafetyFilter`:

```python
from mcp_fuzzer.safety_system.safety import SafetyFilter

custom_filter = SafetyFilter(
    dangerous_url_patterns=[r"https?://", r"example\\.com"],
    dangerous_script_patterns=[r"<script", r"onload="],
    dangerous_command_patterns=[r"rm\\s+-rf", r"shutdown"],
    dangerous_argument_names=["path", "command"],
)
```

Note: the default `SafetyFilter` does not block on these patterns; override
`should_skip_tool_call()` or implement a custom provider to enforce them.

To swap the filesystem sandbox implementation, implement the `SandboxProvider`
protocol and pass it to `SafetyFilter`:

```python
from mcp_fuzzer.safety_system.safety import SandboxProvider, SafetyFilter
from mcp_fuzzer.safety_system.filesystem.sandbox import FilesystemSandbox

class CustomSandbox(SandboxProvider):
    def initialize(self, root: str) -> None:
        ...

    def get_sandbox(self) -> FilesystemSandbox:
        ...

custom_filter = SafetyFilter(sandbox_provider=CustomSandbox())
```

## Minimal Policy Configuration Example

```yaml
safety_enabled: true
enable_safety_system: true
fs_root: "~/.mcp_fuzzer"
no_network: true
allow_hosts:
  - "localhost"
  - "127.0.0.1"
```

## Best Practices

- Always combine `--enable-safety-system` with a sandboxed `--fs-root` when
  targeting untrusted MCP servers.
- Leave argument-level SafetyFilter enabled unless you are fuzzing a
  purpose-built sandbox and understand the risks.
- Treat the safety logs as a signal that the server attempted a risky action.
  Investigate and file bugs upstream when legitimate tools try to open browsers
  or read/write outside the sandbox.
- Store `MCP_FUZZER_FS_ROOT` in a dedicated temporary directory per session so
  cleanup is easier.
