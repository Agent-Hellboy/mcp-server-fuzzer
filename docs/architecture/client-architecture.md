# Client Architecture

The MCP Fuzzer client has been refactored into a modular package structure to improve maintainability, testability, and extensibility. This document describes the new architecture.

## Overview

The client package is organized into several modules, each with a specific responsibility:

```
mcp_fuzzer/
├── client/
│   ├── __init__.py              # Exports client APIs
│   ├── base.py                  # MCPFuzzerClient orchestration
│   ├── main.py                  # Unified runner used by the CLI
│   ├── settings.py              # ClientSettings / config access
│   ├── tool_client.py           # Tool fuzzing functionality
│   ├── protocol_client.py       # Protocol fuzzing functionality
│   ├── runtime/                 # Run plan + execution pipeline
│   ├── transport/               # Transport factory + auth integration
│   ├── adapters/                # Config adapter (port/adapter)
│   ├── ports/                   # Port interfaces
│   └── safety/                  # Safety system wiring
```

## Components

### Base Client (`base.py`)

The `MCPFuzzerClient` class in `base.py` is the main entry point for fuzzing operations. It:

- Integrates the tool and protocol clients
- Manages shared resources like transport and authentication
- Provides high-level fuzzing methods
- Delegates specific functionality to specialized clients
- Handles reporting and cleanup

### Tool Client (`tool_client.py`)

The `ToolClient` class in `tool_client.py` handles all tool-related fuzzing operations:

- Fuzzing individual tools
- Fuzzing all tools from a server
- Two-phase fuzzing (realistic and aggressive)
- Safety checks for tool arguments

### Protocol Client (`protocol_client.py`)

The `ProtocolClient` class in `protocol_client.py` handles all protocol-related fuzzing operations:

- Fuzzing specific protocol types
- Fuzzing all protocol types
- Safety checks for protocol messages
- Sending different types of protocol requests

### Unified Runner (`main.py`)

The unified runner wires CLI settings into the client and run plan:

- Builds the transport with auth via `build_driver_with_auth`
- Initializes `MCPFuzzerClient` and `FuzzerReporter`
- Executes the run plan (tools, spec guard, protocol, stateful)

### Runtime Pipeline (`client/runtime/`)

The runtime package includes:

- `run_plan.py` - Ordered run steps per mode
- `pipeline.py` - Execution pipeline (tools/protocol/resources/prompts/stateful)
- `argv_builder.py` and `async_runner.py` - Inner-argv handling and execution

### Settings and Adapters

- `settings.py` encapsulates merged config into `ClientSettings`.
- `adapters/` + `ports/` provide a Port & Adapter boundary around config access.

## Benefits of the New Architecture

1. **Separation of Concerns**: Each module has a clear, focused responsibility
2. **Reduced Complexity**: Smaller, more manageable classes and methods
3. **Improved Testability**: Easier to write targeted unit tests
4. **Better Extensibility**: New functionality can be added without modifying existing code
5. **Clearer Dependencies**: Dependencies between components are explicit

## Usage

The new client can be used in the same way as the old client:

```python
from mcp_fuzzer.client import MCPFuzzerClient
from mcp_fuzzer.transport.catalog import build_driver

async def fuzz_server():
    transport = build_driver('http', 'http://localhost:8000')
    client = MCPFuzzerClient(transport)
    results = await client.fuzz_all_tools(runs_per_tool=5)
    print(f"Fuzzing results: {results}")

import asyncio
asyncio.run(fuzz_server())
```

## Future Improvements

1. **Plugin Architecture**: Add support for custom fuzzing strategies via plugins
2. **Richer Report Customization**: Expand export styling and templates for HTML/Markdown
3. **Configuration Integration**: Better integration with the configuration system
4. **Metrics Collection**: Add detailed metrics collection for performance monitoring
5. **Async Context Manager**: Implement `__aenter__` and `__aexit__` for use in async with statements
