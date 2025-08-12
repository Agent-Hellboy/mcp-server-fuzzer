# MCP Server Fuzzer

A comprehensive super aggressive CLI based fuzzing tool for MCP servers using multiple transport protocols, with support for both **tool argument fuzzing** and **protocol type fuzzing**. Features pretty output using [rich](https://github.com/Textualize/rich).

The most important thing I'm aiming to ensure here is:
If your server conforms to the [MCP schema](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema), this tool will be able to fuzz it effectively.

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)

## Documentation

**[View Full Documentation](https://agent-hellboy.github.io/mcp-server-fuzzer/)**

## Quick Start

### Installation

```bash
# Install from PyPI
pip install mcp-fuzzer

# Or install from source
git clone https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
pip install -e .
```

### Basic Usage

1. **Set up your MCP server** (HTTP, SSE, or Stdio)
2. **Run basic fuzzing:**

```bash
# Fuzz tools on an HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000

# Fuzz protocol types on an SSE server
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8000/sse
```

## Key Features

- **Two-Phase Fuzzing**: Realistic testing + aggressive security testing
- **Multi-Protocol Support**: HTTP, SSE, and Stdio transports
- **Built-in Safety**: Environment detection and system protection
- **Intelligent Testing**: Hypothesis-based data generation strategies
- **Rich Reporting**: Detailed output with exception tracking

## Architecture

The system is built with a modular architecture:

- **CLI Layer**: User interface and argument handling
- **Transport Layer**: Protocol abstraction (HTTP/SSE/Stdio)
- **Fuzzing Engine**: Test orchestration and execution
- **Strategy System**: Data generation (realistic + aggressive)
- **Safety System**: Core filter + SystemBlocker PATH shim; safe mock responses
- **Runtime**: Async ProcessManager + ProcessWatchdog + AsyncProcessWrapper
- **Authentication**: Multiple auth provider support
- **Reporting**: FuzzerReporter, Console/JSON/Text formatters, SafetyReporter

## Contributing

We welcome contributions! Please see our [Contributing Guide](https://agent-hellboy.github.io/mcp-server-fuzzer/contributing/) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Disclaimer

This tool is designed for testing and security research. Always use in controlled environments and ensure you have permission to test the target systems. The safety system provides protection but should not be relied upon as the sole security measure.
