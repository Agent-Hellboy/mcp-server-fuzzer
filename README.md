# MCP Fuzzer

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-server-fuzzer.svg)](https://pypi.org/project/mcp-server-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-server-fuzzer)](https://pepy.tech/projects/mcp-server-fuzzer)

A CLI tool for fuzzing MCP server tools using JSON-RPC 2.0, with pretty output using [rich](https://github.com/Textualize/rich).

## Features
- Discovers available tools from an MCP server endpoint
- Fuzzes each tool with random/edge-case arguments using Hypothesis
- Reports results and exceptions in a rich terminal table

## Installation


```bash
pip install -e .
```

## Usage

You can run the fuzzer as a CLI tool after install:

```bash
mcp-fuzzer-client --url http://localhost:8000/mcp/ --runs 10
```

Or directly with Python:

```bash
python -m mcp_fuzzer_client --url http://localhost:8000/mcp/ --runs 10
```

- `--url`: URL of the MCP server's JSON-RPC endpoint
- `--runs`: Number of fuzzing runs per tool (default: 10)

## Output

Results are shown in a colorized table, including the number of exceptions and an example error if any.

---

**Project dependencies are managed via `pyproject.toml`.**

Test result of  fuzz testing of https://github.com/modelcontextprotocol/python-sdk/tree/main/examples/servers/simple-streamablehttp-stateless

![fuzzer](./fuzzer.png)
