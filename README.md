# MCP Server Fuzzer

<div align="center">

<img src="icon.png" alt="MCP Server Fuzzer Icon" width="100" height="100">

**CLI fuzzing for MCP servers**

*Tool fuzzing • Protocol fuzzing • HTTP/SSE/stdio/StreamableHTTP • Safety controls • Rich reporting*

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)
[![Supports MCP 2025-11-25](https://img.shields.io/badge/MCP%20Spec-2025--11--25%20Supported-0f766e)](https://modelcontextprotocol.io/specification/2025-11-25/)
[![Docker Pulls](https://img.shields.io/docker/pulls/princekrroshan01/mcp-fuzzer)](https://hub.docker.com/r/princekrroshan01/mcp-fuzzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

[Docs Site](https://agent-hellboy.github.io/mcp-server-fuzzer/) • [Getting Started](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/getting-started/) • [CLI Reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)

</div>

## What It Does

MCP Server Fuzzer tests MCP servers by fuzzing:

- tool arguments
- protocol request types
- resource and prompt request flows
- multiple transports: `http`, `sse`, `stdio`, and `streamablehttp`

It includes optional safety controls such as filesystem sandboxing, PATH-based
command blocking, and network restrictions for safer local testing.

## Findings It Reports

Beyond protocol/transport errors, runs are classified into categorized findings
(written to `<output-dir>/findings.json`, with per-crash repros under
`<output-dir>/crashes/`, a compact CI summary at
`<output-dir>/run_summary.json`, and summarized on stdout):

- `crash` — server process terminated abnormally (segfault/abort/panic or
  non-zero exit); captures the signal and a stderr tail
- `auth_bypass` — a protected tool answered an unauthenticated call
- `injection_reflection` — a dangerous input token was echoed back verbatim
- `oversized_response` — response exceeded the read cap (resource exhaustion)
- `hang` — request timed out (deadlock / infinite loop / ReDoS)
- `internal_error` — JSON-RPC `-32603` (unhandled server-side exception)
- `error_leakage` — stack trace / panic leaked in output
- `memory_growth` — server RSS grew multi-fold across runs (stdio targets)
- `non_determinism` — identical input produced differing outcomes
- `accepted_malformed` — server returned a non-error response to an
  attack-pattern or schema-invalid fuzz input; repeated identical evidence is
  collapsed into one finding with run counts and a response sample
- `performance_outlier` — response time far above the per-target median

`findings.json` is always written for completed sessions, even when no findings
are present (`{"findings": [], "count": 0}`), so CI jobs can assert that report
generation succeeded separately from whether issues were discovered.
`run_summary.json` records whether the run completed or was blocked, plus
tool/protocol counts and run totals for simple CI assertions.

Tip: for compiled-language servers (Go/C/C++/Rust), run the target under a
sanitizer or race build so memory bugs surface as observable crashes.

## Install

Requires Python 3.10+.

```bash
# PyPI
pip install mcp-fuzzer

# From source
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
pip install -e .
```

Docker is also supported:

```bash
docker build -t mcp-fuzzer:latest .
docker run --rm mcp-fuzzer:latest --help
```

## Quick Start

### 1. Run the bundled HTTP example server

```bash
pip install "mcp[cli]" uvicorn
python3 examples/test_server.py
```

That server uses the official Python MCP SDK, listens on
`http://localhost:8000/mcp/`, and exposes:

- `test_tool`
- `echo_tool`
- `secure_tool` requiring `Authorization: Bearer secret123`

### 2. Fuzz tools

```bash
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ --runs 10
```

### 3. Fuzz protocol requests

```bash
mcp-fuzzer --mode protocol --protocol-type InitializeRequest \
  --protocol http --endpoint http://localhost:8000/mcp/ --runs-per-type 5
```

### 4. Run tools and protocol together

```bash
mcp-fuzzer --mode all --phase both --protocol http --endpoint http://localhost:8000/mcp/
```

## Common Commands

```bash
# Enable command blocking + safety reporting
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ \
  --enable-safety-system --safety-report

# Export results
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ \
  --export-csv results.csv --export-html results.html

# Use auth config for the bundled secure_tool example
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/ \
  --auth-config examples/auth_config.json

# Load settings from YAML
mcp-fuzzer --config config.yaml
```

## Example Servers

This repository bundles:

- an official Python MCP SDK HTTP example: [`examples/test_server.py`](examples/test_server.py)
- an official Go MCP SDK stdio example: [`examples/go_stdio_server`](examples/go_stdio_server)
- an official TypeScript MCP SDK stdio example: [`examples/typescript-stdio-server`](examples/typescript-stdio-server)
- a StreamableHTTP example: [`examples/streamable_http_server.py`](examples/streamable_http_server.py)

For other stdio usage, point the fuzzer at your own server:

```bash
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" \
  --enable-safety-system --fs-root /tmp/mcp-safe
```

More runnable example flows are documented in
[`examples/README.md`](examples/README.md).

## Documentation

Keep the README for the basics. Use the docs for everything else:

- [Getting Started](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/getting-started/)
- [Examples](https://agent-hellboy.github.io/mcp-server-fuzzer/getting-started/examples/)
- [Configuration](https://agent-hellboy.github.io/mcp-server-fuzzer/configuration/configuration/)
- [CLI Reference](https://agent-hellboy.github.io/mcp-server-fuzzer/development/reference/)
- [Safety Guide](https://agent-hellboy.github.io/mcp-server-fuzzer/components/safety/)
- [Architecture](https://agent-hellboy.github.io/mcp-server-fuzzer/architecture/architecture/)
- [Contributing](https://agent-hellboy.github.io/mcp-server-fuzzer/development/contributing/)

## License

MIT. See [`LICENSE`](LICENSE).
