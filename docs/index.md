# MCP Server Fuzzer

A comprehensive super aggressive CLI based fuzzing tool for MCP servers using multiple transport protocols, with support for both **tool argument fuzzing** and **protocol type fuzzing**. Features pretty output using [rich](https://github.com/Textualize/rich).

The most important thing I'm aiming to ensure here is:
If your server conforms to the [MCP schema](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema), this tool will be able to fuzz it effectively.

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)

## Quick Start

### Installation

```bash
# Basic installation
pip install mcp-fuzzer

# From source (includes MCP spec submodule)
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
# If you already cloned without submodules, run:
git submodule update --init --recursive
pip install -e .
```

### Basic Usage

1. **Set up your MCP server** (HTTP, SSE, or Stdio)
2. **Run basic fuzzing**:
   ```bash
   # Fuzz tools on an HTTP server
   mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 10

   # Fuzz protocol types on an SSE server
   mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol sse --endpoint http://localhost:8000/sse --runs-per-type 5

   # Fuzz with safety system enabled
   mcp-fuzzer --mode tools --protocol stdio --endpoint "python test_server.py" --runs 5 --enable-safety-system
   ```
3. **View results** in beautiful, colorized tables

## Key Features

### Two-Phase Fuzzing Approach

- **Phase 1: Realistic Fuzzing** - Test with valid, realistic data
- **Phase 2: Aggressive Fuzzing** - Test security and robustness with malicious data

### Multi-Protocol Support

- **HTTP/HTTPS** - Standard HTTP transport with authentication

- **Server-Sent Events (SSE)** - Real-time streaming support

- **Stdio** - Command-line interface for local testing

### Safety & Security

- **Built-in Safety System** - Pattern-based filtering plus safety reports

- **System Command Blocking** - PATH shims stop browser/app launches

- **Filesystem Sandboxing** - Confines file operations

- **Process Isolation** - Safe subprocess handling with timeouts

### Comprehensive Testing

- **Tool Discovery** - Automatically discovers available tools

- **Protocol Coverage** - Tests all major MCP protocol types

- **Edge Case Generation** - Uses Hypothesis + custom strategies

- **Detailed Reporting** - Rich output with exception tracking

### Professional Reporting System

- **Automatic Report Generation** - JSON and text reports for each session

- **Comprehensive Data Collection** - Tool results, protocol results, and safety data

- **Safety Transparency** - Detailed breakdown of blocked operations and risk assessments

- **Multiple Output Formats** - Console, JSON, and text for different use cases

- **Session Tracking** - Timestamped reports with unique session identification

## Architecture

The MCP Fuzzer uses a modular architecture with clear separation of concerns:

- **Transport Layer** - Protocol-agnostic communication

- **Fuzzing Engine** - Modular design with Mutators, Executor, and FuzzerReporter
  - **Mutators** - Data generation and mutation (Tool, Protocol, Batch)
  - **Executor** - Orchestration and concurrency control
  - **FuzzerReporter** - Result collection and metrics

- **Strategy System** - Realistic and aggressive data generation

- **Safety System** - Pattern-based filtering, sandboxing, and PATH shims

- **Reporting System** - Centralized output management and comprehensive reporting

- **Runtime Management** - Async process management and monitoring

- **CLI** - User-friendly command-line interface

See [Architecture Overview](architecture/architecture.md) and [Fuzz Engine Architecture](architecture/fuzz-engine.md) for detailed diagrams and documentation.

## Documentation

### Getting Started

- **[Getting Started](getting-started/getting-started.md)** - Installation and basic usage
- **[Examples](getting-started/examples.md)** - Working examples and configurations

### Architecture

- **[Architecture Overview](architecture/architecture.md)** - System design and components
- **[Fuzz Engine](architecture/fuzz-engine.md)** - Detailed fuzz engine design (Mutators, Executor, FuzzerReporter)
- **[Client Architecture](architecture/client-architecture.md)** - Client package structure
- **[Async Executor](architecture/async-executor.md)** - Async execution framework

### Configuration

- **[Configuration](configuration/configuration.md)** - Configuration options and file formats (YAML)
- **[Network Policy](configuration/network-policy.md)** - Network access control

### Components

- **[Runtime Management](components/runtime-management.md)** - Process management, watchdog system
- **[Process Management Guide](components/process-management-guide.md)** - Process management best practices
- **[Safety Guide](components/safety.md)** - Safety system configuration

### Development

- **[Reference](development/reference.md)** - Complete API reference
- **[Exceptions](development/exceptions.md)** - Error handling and exception hierarchy
- **[Contributing](development/contributing.md)** - Development and contribution guide

### Testing

- **[Fuzz Results](testing/fuzz-results.md)** - Latest fuzzing test results

## Contributing

We welcome contributions. Please see our [Contributing Guide](development/contributing.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Agent-Hellboy/mcp-server-fuzzer/blob/main/LICENSE) file for details.

---

**Made with love for the MCP community**
