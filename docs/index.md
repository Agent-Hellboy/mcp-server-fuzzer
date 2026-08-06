# MCP Server Fuzzer

MCP Server Fuzzer is a command-line security and robustness tester for live [Model Context Protocol](https://modelcontextprotocol.io/) servers.

It supports tool, protocol, resource, and prompt testing over HTTP, HTTPS, SSE, Streamable HTTP, and stdio. Results are written as structured findings so local investigations and CI jobs can use the same output.

## Start here

1. [Install and run your first fuzz session](getting-started/getting-started.md)
2. [Try transport, authentication, and audit examples](getting-started/examples.md)
3. [Configure a repeatable run](configuration/configuration.md)
4. [Understand safety controls and isolation](components/safety.md)
5. [Use the CLI reference](development/reference.md)

## Supported MCP versions

The default protocol version is 2025-11-25. Schema-driven testing supports:

| Version | Support |
| --- | --- |
| 2024-11-05 | Schema-driven fuzzing and protocol checks |
| 2025-03-26 | Schema-driven fuzzing and Streamable HTTP behavior |
| 2025-06-18 | Schema-driven fuzzing and protocol checks |
| 2025-11-25 | Default version, OAuth 2.1 audit path, and current stable workflows |
| 2026-07-28 | Stateless Streamable HTTP and draft-schema compatibility path |

Select a version with --spec-schema-version or spec_schema_version. The server's negotiated protocol version is recorded in the run metadata.

## What the fuzzer reports

Reports can include:

- Reliability: crashes, hangs, timeouts, internal errors, error leakage, oversized responses, and performance outliers.
- Input handling: malformed-input acceptance, injection reflection, nondeterminism, and schema violations.
- MCP security: tool and schema poisoning markers, hidden instructions, ANSI/control content, tool shadowing, dangerous capability combinations, cleartext remote transport, and OAuth metadata issues.
- Runtime behavior: optional process execution, process spawning, network activity, credential reads, filesystem mutation, privilege changes, and ptrace observations for stdio targets.

Findings include structured evidence and relevant OWASP MCP Top 10 links where a mapping is available.

## Safety model

Normal fuzzing does not require the optional runtime monitor. For local stdio targets, combine --enable-safety-system with --fs-root and use --no-network when the server should remain local. Runtime monitoring is opt-in and fail-open; a probe error cannot fail a normal fuzz run.

## Project resources

- [GitHub repository](https://github.com/Agent-Hellboy/mcp-server-fuzzer)
- [PyPI package](https://pypi.org/project/mcp-fuzzer/)
- [Docker image](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer)
- [mcpfz-probe runtime monitor](https://github.com/Agent-Hellboy/mcpfz-probe)
- [Contributing guide](development/contributing.md)
- [Security CI guidance](SECURITY_CI.md)

The architecture section is maintained for contributors and maintainers; users can start with the task-focused guides above.
