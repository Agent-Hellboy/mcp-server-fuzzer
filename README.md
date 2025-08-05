# MCP Fuzzer

A CLI tool for fuzzing MCP server tools using multiple transport protocols, with pretty output using [rich](https://github.com/Textualize/rich).

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)


## Features
- **Multi-Protocol Support**: HTTP, SSE, Stdio, and WebSocket transports
- **Tool Discovery**: Automatically discovers available tools from MCP servers
- **Intelligent Fuzzing**: Uses Hypothesis to generate random/edge-case arguments
- **Rich Reporting**: Beautiful terminal tables with detailed statistics
- **Protocol Flexibility**: Easy to add new transport protocols

## Architecture

The MCP Fuzzer uses a transport abstraction layer to support multiple protocols. Here's how it works:

![mcp_fuzzer_arch](./images/mcp_fuzzer_arch.png)

## Installation

```bash
pip install mcp-fuzzer
```

## Usage

You can run the fuzzer in several ways:

### As a CLI tool (recommended)
```bash
mcp-fuzzer --protocol http --endpoint http://localhost:8000/mcp/ --runs 10
```

### As a Python module
```bash
python -m mcp_fuzzer --protocol http --endpoint http://localhost:8000/mcp/ --runs 10
```

### As a Python script
```bash
python -m mcp_fuzzer.client --protocol http --endpoint http://localhost:8000/mcp/ --runs 10
```

## Supported Protocols

### HTTP Transport
```bash
mcp-fuzzer --protocol http --endpoint http://localhost:8080/rpc --runs 20
```

### SSE Transport
```bash
mcp-fuzzer --protocol sse --endpoint http://localhost:8080/sse --runs 15
```

### Stdio Transport
```bash
# Binary executables
mcp-fuzzer --protocol stdio --endpoint "./bin/mcp-shell" --runs 10

# Python scripts
mcp-fuzzer --protocol stdio --endpoint "python3 ./my-mcp-server.py" --runs 10

# Python scripts with spaces in path
mcp-fuzzer --protocol stdio --endpoint '"./My Server/mcp-server.py"' --runs 10
```

### WebSocket Transport
```bash
mcp-fuzzer --protocol websocket --endpoint ws://localhost:8080/ws --runs 25
```

### Arguments
- `--protocol`: Transport protocol to use (http, sse, stdio, websocket)
- `--endpoint`: Server endpoint (URL for http/sse/websocket, command for stdio)
- `--runs`: Number of fuzzing runs per tool (default: 10)
- `--timeout`: Request timeout in seconds (default: 30.0)
- `--verbose`: Enable verbose logging

## Output

Results are shown in a colorized table with detailed statistics:
- **Success Rate**: Percentage of successful tool calls
- **Exception Count**: Number of exceptions during fuzzing
- **Example Exceptions**: Sample error messages for debugging
- **Overall Statistics**: Summary across all tools and protocols

---

**Project dependencies are managed via `pyproject.toml`.**

Test result of  fuzz testing of https://github.com/modelcontextprotocol/python-sdk/tree/main/examples/servers/simple-streamablehttp-stateless

![fuzzer](./images/fuzzer.png)
