# MCP Server Fuzzer

CLI security and robustness testing for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers.

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/tests.yml)
[![Lint](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![Codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)
[![MCP versions](https://img.shields.io/badge/MCP-2024--11--05%20%7C%202025--03--26%20%7C%202025--06--18%20%7C%202025--11--25%20%7C%202026--07--28-0f766e)](https://modelcontextprotocol.io/specification/2025-11-25/)
[![Docker pulls](https://img.shields.io/docker/pulls/princekrroshan01/mcp-fuzzer)](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776ab)](https://www.python.org/downloads/)

**[Documentation](https://agent-hellboy.github.io/mcp-server-fuzzer/)** | **[Getting started](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/getting-started/)** | **[CLI reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)** | **[Releases](https://github.com/Agent-Hellboy/mcp-server-fuzzer/releases)**

## What it tests

MCP Server Fuzzer exercises live servers through:

- Tool argument generation and mutation, including realistic and aggressive inputs.
- Protocol request fuzzing and schema-aware checks.
- Resources and prompts workflows.
- HTTP, HTTPS, SSE, Streamable HTTP, and stdio transports.
- Authentication and OAuth metadata checks for authorized remote testing.
- Tool metadata and schema security checks, including hidden instructions, tool shadowing, unsafe capability combinations, and output injection indicators.
- Optional runtime monitoring for stdio servers through [mcpfz-probe](https://github.com/Agent-Hellboy/mcpfz-probe).

The default protocol version is 2025-11-25. Schema-driven testing supports 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and 2026-07-28; select a target version with --spec-schema-version.

## Install

Requires Python 3.10 or newer.

```bash
python -m pip install mcp-fuzzer
```

For optional runtime monitoring:

```bash
python -m pip install "mcp-fuzzer[mcpfz-probe]"
```

Docker images are published to [princekrroshan01/mcp-fuzzer](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer):

```bash
docker pull princekrroshan01/mcp-fuzzer:latest
docker run --rm princekrroshan01/mcp-fuzzer:latest --help
```

## Quick start

Run a local or remote MCP server, then point the fuzzer at its endpoint:

```bash
mcp-fuzzer \
  --mode tools \
  --protocol streamablehttp \
  --endpoint http://localhost:8000/mcp \
  --runs 10 \
  --security-audit \
  --output-dir reports
```

For a local stdio server:

```bash
mcp-fuzzer \
  --mode all \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --enable-safety-system \
  --fs-root "$PWD/fuzz-sandbox" \
  --output-dir reports
```

Only test servers and endpoints you are authorized to assess. Use low run counts first, configure timeouts, and isolate local servers with --fs-root, --no-network, or a container.

## Findings and reports

Completed sessions write reports to the selected output directory:

- findings.json: normalized security and reliability findings with evidence, severity, target, run, and source links.
- run_summary.json: machine-readable completion status and session counts.
- crashes/: crash reproductions and related server output when available.
- Optional CSV, XML, HTML, and Markdown exports from the --export-* options.

Findings can include crashes, hangs, malformed-input acceptance, internal errors, error leakage, oversized responses, authentication exposure, injection reflection, nondeterminism, performance outliers, tool poisoning, and runtime observations such as process execution, network activity, credential reads, filesystem mutation, or ptrace.

Security findings include links to the relevant [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) category where applicable. The fuzzer reports evidence; it does not prove exploitability in every environment.

## Security audits

Add --security-audit to inspect tool descriptions and schemas and to evaluate security-relevant fuzz output. Add --auth-audit for OAuth metadata and authorization checks. Intrusive authorization probes require --auth-audit-intrusive and explicit authorization.

For CI, use --fail-if-no-tools, store findings.json as an artifact, and gate the job on the finding policy appropriate for your project.

## Runtime monitoring

Runtime monitoring is opt-in and fail-open. It applies to stdio server processes and uses the external mcpfz-probe sidecar; it is disabled by default and never required for normal fuzzing.

```bash
mcp-fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "python my_server.py" \
  --runtime-probe \
  --runtime-probe-backend auto \
  --runtime-probe-bin /path/to/mcpfz-probe \
  --runs 3 \
  --output-dir reports
```

Use the fake backend for portable development and tests. The ebpf backend is Linux-specific and may require the capabilities documented by [mcpfz-probe](https://github.com/Agent-Hellboy/mcpfz-probe). Use allowlists for expected helper executables and hosts. Never use runtime monitoring against a server or host you do not control.

## Documentation

- [Getting started](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/getting-started/)
- [Examples](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/examples/)
- [Configuration](https://agent-hellboy.github.io/mcp-server-fuzzer/configuration/configuration/)
- [Safety and isolation](https://agent-hellboy.github.io/mcp-server-fuzzer/components/safety/)
- [Security CI guidance](https://agent-hellboy.github.io/mcp-server-fuzzer/security-ci/)
- [CLI reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)
- [Contributing](https://agent-hellboy.github.io/mcp-server-fuzzer/development/contributing/)

Architecture pages remain available for contributors who need implementation context.

## License

MIT. See [LICENSE](LICENSE).
