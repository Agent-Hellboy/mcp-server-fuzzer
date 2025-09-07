# MCP Server Fuzzer

<div align="center">

**A comprehensive super-aggressive CLI-based fuzzing tool for MCP servers**

*Multi-protocol support • Two-phase fuzzing • Built-in safety • Rich reporting • async runtime and async fuzzing of mcp tools*

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

[Documentation](https://agent-hellboy.github.io/mcp-server-fuzzer/) • [Quick Start](#quick-start) • [Examples](#examples) • [Configuration](#configuration)

</div>

---

## What is MCP Server Fuzzer?

MCP Server Fuzzer is a comprehensive fuzzing tool designed specifically for testing [Model Context Protocol (MCP)](https://github.com/modelcontextprotocol/modelcontextprotocol) servers. It supports both tool argument fuzzing and protocol type fuzzing across multiple transport protocols.

### Key Promise

If your server conforms to the [MCP schema](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema), this tool will fuzz it effectively and safely.

### Why Choose MCP Server Fuzzer?

- Safety First: Built-in safety system prevents dangerous operations
- High Performance: Asynchronous execution with configurable concurrency
- Beautiful Output: Rich, colorized terminal output with detailed reporting
- Flexible Configuration: CLI args, YAML configs, environment variables
- Comprehensive Reporting: Multiple output formats (JSON, CSV, HTML, Markdown)
- Production Ready: Environment detection and production-safe defaults
- Intelligent Testing: Hypothesis-based data generation with custom strategies

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

### Advanced Usage

```bash
# Two-phase fuzzing (realistic + aggressive)
mcp-fuzzer --mode both --phase both --protocol http --endpoint http://localhost:8000

# With safety system enabled
mcp-fuzzer --mode tools --enable-safety-system --safety-report

# Export results to multiple formats
mcp-fuzzer --mode tools --export-csv results.csv --export-json results.json

# Use configuration file
mcp-fuzzer --config my-config.yaml --server production_api
```

## Examples

### HTTP Server Fuzzing

```bash
# Basic HTTP fuzzing
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000 --runs 50

# With authentication
mcp-fuzzer --mode tools --protocol http --endpoint https://api.example.com \
           --auth-config auth.json --runs 100
```

### SSE Server Fuzzing

```bash
# SSE protocol fuzzing
mcp-fuzzer --mode protocol --protocol sse --endpoint http://localhost:8080/sse \
           --runs-per-type 25 --verbose
```

### Stdio Server Fuzzing

```bash
# Local server testing
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" \
           --enable-safety-system --fs-root /tmp/safe
```

### Configuration File Usage

```yaml
# config.yaml
servers:
  local_dev:
    protocol: stdio
    endpoint: "python dev_server.py"
    runs: 10
    phase: realistic

  production:
    protocol: http
    endpoint: "https://api.prod.com"
    runs: 100
    phase: both
    auth:
      type: api_key
      api_key: "${API_KEY}"
```

```bash
mcp-fuzzer --config config.yaml --server local_dev
```

## Configuration

### Configuration Methods (in order of precedence)

1. **Command-line arguments** (highest precedence)
2. **Configuration files** (YAML/TOML)
3. **Environment variables** (lowest precedence)

### Environment Variables

```bash
# Core settings
export MCP_FUZZER_TIMEOUT=60.0
export MCP_FUZZER_LOG_LEVEL=DEBUG
export MCP_FUZZER_VERBOSE=true

# Safety settings
export MCP_FUZZER_SAFETY_ENABLED=true
export MCP_FUZZER_FS_ROOT=/tmp/safe

# Authentication
export MCP_API_KEY="your-api-key"
export MCP_USERNAME="your-username"
export MCP_PASSWORD="your-password"
```

### Performance Tuning

```bash
# High concurrency for fast networks
mcp-fuzzer --process-max-concurrency 20 --watchdog-check-interval 0.5

# Conservative settings for slow/unreliable servers
mcp-fuzzer --timeout 120 --process-retry-count 5 --process-retry-delay 2.0
```

## Key Features

| Feature | Description |
|---------|-------------|
| Two-Phase Fuzzing | Realistic testing + aggressive security testing |
| Multi-Protocol Support | HTTP, SSE, Stdio, and StreamableHTTP transports |
| Built-in Safety | Environment detection and system protection |
| Intelligent Testing | Hypothesis-based data generation with custom strategies |
| Rich Reporting | Detailed output with exception tracking and safety reports |
| Multiple Output Formats | JSON, CSV, HTML, Markdown, and XML export options |
| Flexible Configuration | CLI args, YAML/TOML configs, environment variables |
| Asynchronous Execution | Efficient concurrent fuzzing with configurable limits |
| Comprehensive Monitoring | Process watchdog, timeout handling, and resource management |
| Authentication Support | API keys, basic auth, OAuth, and custom providers |
| Performance Metrics | Built-in benchmarking and performance analysis |
| Schema Validation | Automatic MCP protocol compliance checking |

### Performance

- Concurrent Operations: Up to 20 simultaneous fuzzing tasks
- Memory Efficient: Streaming responses and configurable resource limits
- Fast Execution: Optimized async I/O and connection pooling
- Scalable: Configurable timeouts and retry mechanisms

## Architecture

The system is built with a modular architecture:

- **CLI Layer**: User interface and argument handling
- **Transport Layer**: Protocol abstraction (HTTP/SSE/Stdio)
- **Fuzzing Engine**: Test orchestration and execution
- **Strategy System**: Data generation (realistic + aggressive)
- **Safety System**: Core filter + SystemBlocker PATH shim; safe mock responses
- **Runtime**: Fully async ProcessManager + ProcessWatchdog
- **Authentication**: Multiple auth provider support
- **Reporting**: FuzzerReporter, Console/JSON/Text formatters, SafetyReporter

## Troubleshooting

### Common Issues

**Connection Timeout**
```bash
# Increase timeout for slow servers
mcp-fuzzer --timeout 120 --endpoint http://slow-server.com
```

**Authentication Errors**
```bash
# Check auth configuration
mcp-fuzzer --check-env
mcp-fuzzer --validate-config config.yaml
```

**Memory Issues**
```bash
# Reduce concurrency for memory-constrained environments
mcp-fuzzer --process-max-concurrency 2 --runs 25
```

**Permission Errors**
```bash
# Run with appropriate permissions or use safety system
mcp-fuzzer --enable-safety-system --fs-root /tmp/safe
```

### Debug Mode

```bash
# Enable verbose logging
mcp-fuzzer --verbose --log-level DEBUG

# Check environment
mcp-fuzzer --check-env
```

## Community & Support

- Documentation: [Full Documentation](https://agent-hellboy.github.io/mcp-server-fuzzer/)
- Issues: [GitHub Issues](https://github.com/Agent-Hellboy/mcp-server-fuzzer/issues)
- Discussions: [GitHub Discussions](https://github.com/Agent-Hellboy/mcp-server-fuzzer/discussions)
- Security: For security issues, please email [security@example.com](mailto:security@example.com)

### Contributing

We welcome contributions! Please see our [Contributing Guide](https://agent-hellboy.github.io/mcp-server-fuzzer/development/contributing/) for details.

**Quick Start for Contributors:**
```bash
git clone https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
pip install -e .[dev]
pytest tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for testing and security research purposes only.

- Always use in controlled environments
- Ensure you have explicit permission to test target systems
- The safety system provides protection but should not be relied upon as the sole security measure
- Use at your own risk

---

<div align="center">

Made with love for the MCP community

[Star us on GitHub](https://github.com/Agent-Hellboy/mcp-server-fuzzer) • [Read the Docs](https://agent-hellboy.github.io/mcp-server-fuzzer/)

</div>
