# Safety and Isolation

MCP Server Fuzzer can test aggressive inputs while limiting what a local target can do on the host. These controls are opt-in except for argument-level handling.

## Recommended local setup

Use a dedicated sandbox and deny external network access when testing an untrusted stdio server:

```bash
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --no-network \
  --runs 10 \
  --output-dir reports
```

Create a fresh sandbox per session and remove it after reviewing the results. A sandbox is a test boundary, not a replacement for a container or VM.

## Controls

| Control | Purpose |
| --- | --- |
| --enable-safety-system | Blocks selected desktop launchers and browser commands through temporary command shims. |
| --fs-root PATH | Rewrites filesystem paths used in fuzz inputs into a dedicated root. |
| --no-network | Restricts outbound network access to local hosts. |
| --allow-host HOST | Adds an explicitly approved host when --no-network is enabled. |
| --safety-report | Prints blocked-operation information at the end of a run. |
| --export-safety-data FILE | Saves safety information as JSON. |
| --runtime-probe | Enables optional OS-level observations for stdio targets. |

Argument-level safety is enabled by default. Use --no-safety only when the test environment is already isolated and you understand the consequences.

## Runtime monitoring

The optional mcpfz-probe sidecar observes process, network, credential, filesystem, privilege, and ptrace activity for stdio server calls. It is disabled by default, requires separate installation, and fails open if it cannot start.

Use --runtime-probe-backend fake for portable tests or auto to select eBPF when the host supports it. eBPF is intended for an isolated Linux runner. It does not scope remote HTTP, HTTPS, SSE, or Streamable HTTP servers.

See the [runtime monitoring setup](../getting-started/getting-started.md#enable-runtime-monitoring) and the [mcpfz-probe project](https://github.com/Agent-Hellboy/mcpfz-probe) for installation and checksum verification.

## Interpreting safety results

A blocked operation means the fuzzer's boundary intercepted an attempted action. A runtime finding means the sidecar observed behavior. Both are evidence for investigation; neither alone establishes intent or exploitability.

Review:

- the tool name and run identifier;
- the target path, command, or host;
- whether the action was expected for that tool;
- the server's stderr and reproduction data;
- the matching OWASP MCP Top 10 link when present.

## CI guidance

For CI, run the target in a disposable job or container, set bounded timeouts, and upload only redacted reports. See [Security Testing in CI](../SECURITY_CI.md).
