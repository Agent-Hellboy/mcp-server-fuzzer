# MCP Server Fuzzer

<div align="center">

<img src="icon.png" alt="MCP Server Fuzzer Icon" width="100" height="100">

**A comprehensive super-aggressive CLI-based fuzzing tool for MCP servers**

*Multi-protocol support • Two-phase fuzzing • Built-in safety • Rich reporting • async runtime and async fuzzing of mcp tools*

[![CI](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml/badge.svg)](https://github.com/Agent-Hellboy/mcp-server-fuzzer/actions/workflows/lint.yml)
[![codecov](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer/graph/badge.svg?token=HZKC5V28LS)](https://codecov.io/gh/Agent-Hellboy/mcp-server-fuzzer)
[![PyPI - Version](https://img.shields.io/pypi/v/mcp-fuzzer.svg)](https://pypi.org/project/mcp-fuzzer/)
[![PyPI Downloads](https://static.pepy.tech/badge/mcp-fuzzer)](https://pepy.tech/projects/mcp-fuzzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

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
- Production Ready: PATH shims, sandbox defaults, and CI-friendly controls
- Intelligent Testing: Hypothesis-based data generation with custom strategies
- More Than Conformance: Goes beyond the checks in [modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance) with fuzzing, reporting, and safety tooling

### Fuzzing Paradigms

MCP Server Fuzzer combines:

- Grammar/protocol-based fuzzing (schema-driven MCP request generation)
- Black-box fuzzing (no instrumentation; feedback from responses/spec checks)

It does **not** use instrumentation-based fuzzing (no coverage or binary/source instrumentation).

### Basic Fuzzer Flow

```mermaid
flowchart TB
    subgraph CLI["CLI + Config"]
        A1[parse_arguments]
        A2[ValidationManager]
        A3[build_cli_config]
        A4[ClientSettings]
        A1 --> A2 --> A3 --> A4
    end

    subgraph Runtime["Runtime Orchestration"]
        B1[run_with_retry_on_interrupt]
        B2[unified_client_main]
        B3[RunPlan + Commands]
        B4[ClientExecutionPipeline]
        B1 --> B2 --> B3 --> B4
    end

    subgraph Transport["Transport Layer"]
        C1[DriverCatalog + build_driver]
        C2[TransportDriver]
        C3[HttpDriver / SseDriver / StdioDriver / StreamHttpDriver]
        C4[JsonRpcAdapter]
        C5[RetryingTransport (optional)]
        C1 --> C2 --> C3
        C3 --> C4
        C3 --> C5
    end

    subgraph Clients["Client Layer"]
        D1[MCPFuzzerClient]
        D2[ToolClient]
        D3[ProtocolClient]
        D1 --> D2
        D1 --> D3
    end

    subgraph Mutators["Mutators + Strategies"]
        E1[ToolMutator]
        E2[ProtocolMutator]
        E3[ToolStrategies / ProtocolStrategies]
        E4[SeedPool + mutate_seed_payload]
        E1 --> E3
        E2 --> E3
        E1 --> E4
        E2 --> E4
    end

    subgraph Execution["Execution + Concurrency"]
        F1[AsyncFuzzExecutor]
        F2[ToolExecutor]
        F3[ProtocolExecutor]
        F4[ResultBuilder]
        F1 --> F2
        F1 --> F3
        F2 --> F4
        F3 --> F4
    end

    subgraph Safety["Safety System"]
        G1[SafetyFilter + DangerDetector]
        G2[Filesystem Sandbox]
        G3[System Command Blocker]
        G4[Network Policy]
        G1 --> G2
        G1 --> G3
        G1 --> G4
    end

    subgraph RuntimeMgr["Process Runtime"]
        H1[ProcessManager]
        H2[ProcessWatchdog]
        H3[SignalDispatcher]
        H4[ProcessSupervisor]
        H1 --> H2
        H1 --> H3
        H4 --> H1
    end

    subgraph Reporting["Reporting + Output"]
        I1[FuzzerReporter]
        I2[FormatterRegistry]
        I3[OutputProtocol + OutputManager]
        I4[Console/JSON/CSV/XML/HTML/MD Formatters]
        I1 --> I2 --> I4
        I1 --> I3
    end

    A4 --> B1
    B4 --> D1
    C1 --> D1
    D2 --> E1
    D3 --> E2
    E1 --> F2
    E2 --> F3
    D1 --> G1
    C3 --> H4
    D1 --> I1
```

### Extensibility for Contributors
MCP Server Fuzzer is designed for easy extension while keeping CLI usage simple:

- **Custom Transports**: Add support for new protocols via config or self-registration (see [docs/transport/custom-transports.md](docs/transport/custom-transports.md)).
- **Pluggable Safety**: Swap safety providers for custom filtering rules.
- **Injectable Components**: Advanced users can inject custom clients/reporters for testing or plugins.

The modularity improvements (dependency injection, registries) make it maintainer-friendly without complicating the core CLI experience.

## Quick Start

### Installation

Requires Python 3.10+ (editable installs from source also need a modern `pip`).

```bash
# Install from PyPI
pip install mcp-fuzzer

# Or install from source (includes MCP spec submodule)
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
# If you already cloned without submodules, run:
git submodule update --init --recursive
pip install -e .
```

### Docker Installation

The easiest way to use MCP Server Fuzzer is via Docker:

```bash
# Build the Docker image
docker build -t mcp-fuzzer:latest .

# Or pull the published image
# docker pull princekrroshan01/mcp-fuzzer:latest
```

The container ships with `mcp-fuzzer` as the entrypoint, so you pass CLI args
after the image name. Use `/output` for reports and mount any server/config
inputs you need.

```bash
# Show CLI help
docker run --rm mcp-fuzzer:latest --help

# Example: store reports on the host
docker run --rm -v $(pwd)/reports:/output mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 \
  --output-dir /output
```

Required mounts (stdio/config workflows):
- `/output`: writeable reports directory
- `/servers`: read-only server code/executables for stdio
- `/config`: read-only config directory

### Basic Usage

1. **Set up your MCP server** (HTTP, SSE, or Stdio)
2. **Run basic fuzzing:**

**Using Docker:**

```bash
# Fuzz HTTP server (container acts as client)
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000

# Fuzz stdio server (server runs in containerized environment)
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "node /servers/my-server.js stdio"
```

**Using Local Installation:**
```bash
# Fuzz tools on an HTTP server
mcp-fuzzer --mode tools --protocol http --endpoint http://localhost:8000

# Fuzz protocol types on an SSE server
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol sse --endpoint http://localhost:8000/sse
```

### Advanced Usage

```bash
# Two-phase fuzzing (realistic + aggressive)
mcp-fuzzer --mode all --phase both --protocol http --endpoint http://localhost:8000

# With safety system enabled
mcp-fuzzer --mode tools --enable-safety-system --safety-report

# Export results to multiple formats
mcp-fuzzer --mode tools --export-csv results.csv --export-html results.html

# Use configuration file
mcp-fuzzer --config my-config.yaml
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
mcp-fuzzer --mode protocol --protocol-type InitializeRequest --protocol sse --endpoint http://localhost:8080/sse \
           --runs-per-type 25 --verbose
```

### Stdio Server Fuzzing

**Using Docker (Recommended for Isolation):**

```bash
# Server runs in containerized environment for safety
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "python /servers/my_server.py" \
  --enable-safety-system --fs-root /tmp/safe \
  --output-dir /output

# Using docker-compose (easier configuration)
docker-compose run --rm fuzzer \
  --mode tools --protocol stdio --endpoint "node /servers/my-server.js stdio" \
  --runs 50 --output-dir /output
```

**Using Local Installation:**
```bash
# Local server testing
mcp-fuzzer --mode tools --protocol stdio --endpoint "python my_server.py" \
           --enable-safety-system --fs-root /tmp/safe
```

### Configuration File Usage

```yaml
# config.yaml
mode: tools
protocol: stdio
endpoint: "python dev_server.py"
runs: 10
phase: realistic

# Optional output configuration
output:
  directory: "reports"
  format: "json"
  types:
    - "fuzzing_results"
    - "safety_summary"
```

```bash
mcp-fuzzer --config config.yaml
```

## Docker Usage

MCP Server Fuzzer can be run in a Docker container, providing isolation and easy deployment. This is especially useful for:

- **Stdio Servers**: Run servers in a containerized environment for better isolation and safety
- **HTTP/SSE Servers**: Container acts as the MCP client (server can run anywhere)
- **CI/CD Pipelines**: Consistent testing environment across different systems

### Quick Start with Docker

```bash
# Build the image
docker build -t mcp-fuzzer:latest .

# Fuzz HTTP server (server can be on host or remote)
docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol http --endpoint http://localhost:8000 --output-dir /output

# Fuzz stdio server (server code mounted from host)
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools --protocol stdio --endpoint "python /servers/my_server.py" --output-dir /output
```

### Docker Releases

Docker images are published automatically on every GitHub Release (tagged `v*`)
via CI. The published image is:

```bash
docker pull princekrroshan01/mcp-fuzzer:latest
```

Note: The runtime image includes `curl` and `ca-certificates` so stdio servers can fetch HTTPS resources (e.g., schemas, tokens, metadata) without bundling extra tools. If your servers never make outbound HTTPS calls, you can remove them.

### Using Docker Compose

For easier configuration and management, use `docker-compose.yml`:

```bash
# Set environment variables (optional)
export SERVER_PATH=./servers
export CONFIG_PATH=./examples/config
export MCP_SPEC_SCHEMA_VERSION=2025-06-18

# Run fuzzing (stdio server)
docker-compose run --rm fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "node /servers/my-server.js stdio" \
  --runs 50 \
  --output-dir /output

# For HTTP servers (macOS/Windows - uses host.docker.internal)
docker-compose run --rm fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://host.docker.internal:8000 \
  --runs 50 \
  --output-dir /output

# For HTTP servers on Linux (use host network)
docker-compose -f docker-compose.host-network.yml run --rm fuzzer \
  --mode tools \
  --protocol http \
  --endpoint http://localhost:8000 \
  --runs 50 \
  --output-dir /output

# Production-style (no TTY/stdin)
docker-compose -f docker-compose.prod.yml run --rm fuzzer \
  --mode tools \
  --protocol stdio \
  --endpoint "node /servers/my-server.js stdio" \
  --runs 50 \
  --output-dir /output
```

### Docker Volume Mounts

- **`/output`**: Mount your reports directory here (e.g., `-v $(pwd)/reports:/output`)
- **`/servers`**: Mount server code/executables for stdio servers (read-only recommended)
- **`/config`**: Mount custom configuration files if needed

### Network Configuration

- **HTTP/SSE Servers**: Network access required. Linux: prefer `--network host` so `localhost` works. Docker Desktop (macOS/Windows): use `host.docker.internal` since host networking is limited. If neither works, use the host IP.
- **Stdio Servers**: No network needed - server runs as subprocess in container

### Example: Fuzzing a Node.js Stdio Server

```bash
# 1. Prepare your server
mkdir -p servers
cp my-mcp-server.js servers/

# 2. Run fuzzer in Docker
docker run --rm -it \
  -v $(pwd)/servers:/servers:ro \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode all \
  --protocol stdio \
  --endpoint "node /servers/my-mcp-server.js stdio" \
  --runs 100 \
  --enable-safety-system \
  --output-dir /output \
  --export-json /output/results.json
```

### Example: Fuzzing an HTTP Server

```bash
# Server runs on host at localhost:8000
# Container connects to it as client

docker run --rm -it --network host \
  -v $(pwd)/reports:/output \
  mcp-fuzzer:latest \
  --mode tools \
  --protocol http \
  --endpoint http://localhost:8000 \
  --runs 50 \
  --output-dir /output
```

### Security Considerations

- The Docker container runs as non-root user (UID 1000) for improved security
- Stdio servers run in isolated container environment
- Use read-only mounts (`:ro`) for server code when possible
- Reports are written to mounted volume, not inside container

## Configuration

### Configuration Methods (in order of precedence)

1. **Command-line arguments** (highest precedence)
2. **Configuration files** (YAML)
3. **Environment variables** (lowest precedence)

### Environment Variables

```bash
# Core settings
export MCP_FUZZER_TIMEOUT=60.0
export MCP_FUZZER_LOG_LEVEL=DEBUG

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
| Built-in Safety | Pattern-based filtering, sandboxing, and PATH shims |
| Intelligent Testing | Hypothesis-based data generation with custom strategies |
| Rich Reporting | Detailed output with exception tracking and safety reports |
| Multiple Output Formats | JSON, CSV, HTML, Markdown, and XML export options |
| Flexible Configuration | CLI args, YAML configs, environment variables |
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

### Runtime Watchdog Overview

The watchdog supervises processes registered through `ProcessManager`, combining hang detection, signal dispatch, and registry-driven cleanup. For a deeper dive into lifecycle events, custom signal strategies, and registry wiring, see the [runtime management guide](docs/components/runtime-management.md).

### Understanding the Design Patterns

For developers (beginners to intermediate) who want to understand the design patterns used throughout the codebase, please refer to our comprehensive [Design Pattern Review](docs/design-pattern-review.md). This document provides:

- Module-by-module pattern analysis
- Design pattern fit scores and recommendations
- Modularity observations and improvement suggestions
- Complete pattern map for every module in the codebase

This is especially helpful if you're:
- Learning about design patterns in real-world applications
- Planning to contribute to the project
- Wanting to understand the architectural decisions
- Looking for areas to improve or extend

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

### Contributing

We welcome contributions! Please see our [Contributing Guide](https://agent-hellboy.github.io/mcp-server-fuzzer/development/contributing/) for details.

**Quick Start for Contributors:**
```bash
git clone --recursive https://github.com/Agent-Hellboy/mcp-server-fuzzer.git
cd mcp-server-fuzzer
# If you already cloned without submodules, run:
git submodule update --init --recursive
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

## Funding & Support

If you find this project helpful, please consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/github/sponsors/Agent-Hellboy?logo=github&color=ea4aaa)](https://github.com/sponsors/Agent-Hellboy)

**Ways to support:**
- ⭐ **Star the repository** - helps others discover the project
- 🐛 **Report issues** - help improve the tool
- 💡 **Suggest features** - contribute ideas for new functionality
- 💰 **Sponsor on GitHub** - directly support ongoing development
- 📖 **Share the documentation** - help others learn about MCP fuzzing

Your support helps maintain and improve this tool for the MCP community!

---

<div align="center">

Made with love for the MCP community

[Star us on GitHub](https://github.com/Agent-Hellboy/mcp-server-fuzzer) • [Read the Docs](https://agent-hellboy.github.io/mcp-server-fuzzer/)

</div>
