# MCP Server Fuzzer

<div align="center">

<img src="icon.png" alt="MCP Server Fuzzer Icon" width="100" height="100">

**CLI fuzzing for MCP servers**

*Tool fuzzing • Protocol fuzzing • HTTP/SSE/stdio/StreamableHTTP • Safety controls • Rich reporting*

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
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
python3 examples/test_server.py
```

That server listens on `http://localhost:8000` and exposes:

- `test_tool`
- `echo_tool`
- `secure_tool` requiring `Authorization: Bearer secret123`

### 2. Fuzz tools

```bash
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10
```

### 3. Fuzz protocol requests

```bash
mcp-fuzzer --mode protocol --protocol-type InitializeRequest \
  --protocol http --endpoint http://localhost:8000 --runs-per-type 5
```

### 4. Run tools and protocol together

```bash
mcp-fuzzer --mode all --phase both --protocol http --endpoint http://localhost:8000
```

## Common Commands

```bash
# Enable command blocking + safety reporting
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 \
  --enable-safety-system --safety-report

# Export results
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 \
  --export-csv results.csv --export-html results.html

# Use auth config for the bundled secure_tool example
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 \
  --auth-config examples/auth_config.json

# Load settings from YAML
mcp-fuzzer --config config.yaml
```

## Example Servers

This repository bundles:

- an HTTP example server: [`examples/test_server.py`](examples/test_server.py)
- a StreamableHTTP example: [`examples/streamable_http_server.py`](examples/streamable_http_server.py)

It does **not** currently bundle a stdio example server. For stdio usage, point
the fuzzer at your own server:

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
