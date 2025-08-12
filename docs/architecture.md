# Architecture

This document describes the architecture and design of the MCP Server Fuzzer system.

## System Overview

The MCP Server Fuzzer is built with a modular, layered architecture that separates concerns and provides clear interfaces between components. The system is designed to be:

- **Protocol Agnostic**: Fuzzer logic is independent of transport protocols
- **Extensible**: Easy to add new transport protocols and fuzzing strategies
- **Safe**: Built-in safety mechanisms protect against dangerous operations
- **Testable**: Each component can be tested independently

## 🧩 Core Components

### High-Level Architecture

```mermaid
graph TB
    subgraph "CLI Layer"
        A1[Argument Parser]
        A2[Main CLI Entry Point]
        A3[Runner Logic]
    end

    subgraph "Unified Client Layer"
        B1[Start/Stop System]
        B2[System Blocker]
        B3[Tool/Protocol Orchestration]
    end

    subgraph "Transport Layer"
        C1[HTTP Transport]
        C2[SSE Transport]
        C3[Stdio Transport]
    end

    subgraph "Fuzzing Engine"
        D1[Tool Fuzzer]
        D2[Protocol Fuzzer]
        D3[Strategy Manager]
    end

    subgraph "Safety System"
        E1[Core Safety Logic]
        E2[System Blocker]
        E3[Environment Detection]
    end

    A1 --> B1
    A2 --> B2
    A3 --> B3

    B1 --> C1
    B2 --> C2
    B3 --> C3

    C1 --> D1
    C2 --> D2
    C3 --> D3

    D1 --> E1
    D2 --> E2
    D3 --> E3
```

## 🔄 Data Flow

### Main Execution Flow

```mermaid
graph TD
    A[CLI Entry Point] --> B[Parse Arguments]
    B --> C[Create Transport]
    C --> D[Initialize Client]
    D --> E[Discover Tools]
    E --> F[Select Fuzzing Mode]

    F --> G{Mode?}
    G -->|Tools| H[Tool Fuzzer]
    G -->|Protocol| I[Protocol Fuzzer]

    H --> J[Generate Test Data]
    I --> K[Generate Protocol Messages]

    J --> L[Execute Tests]
    K --> M[Execute Protocol Tests]

    L --> N[Collect Results]
    M --> O[Collect Results]

    N --> P[Generate Report]
    O --> Q[Generate Report]

    P --> R[Display Results]
    Q --> R[Display Results]
```

### Safety System Flow

```mermaid
graph TD
    A[Input Request] --> B{Environment Check}
    B -->|Production| C[Apply Safety Rules]
    B -->|Development| D[Check Safety Level]

    C --> E[Block Dangerous Ops]
    D --> F{Operation Type?}

    F -->|Safe| G[Allow Operation]
    F -->|Dangerous| H[Apply Safety Filter]

    E --> I[Log Blocked Operation]
    H --> J[Sanitize Input]

    I --> K[Return Safe Response]
    J --> L[Execute Operation]

    K --> M[End]
    L --> M[End]
```

## 📁 Project Structure

```
mcp_fuzzer/
├── cli/                    # Command-line interface
│   ├── __init__.py
│   ├── args.py            # Argument parsing and validation
│   ├── main.py            # Main CLI entry point
│   └── runner.py          # CLI execution logic
├── transport/              # Transport layer implementations
│   ├── __init__.py
│   ├── base.py            # Abstract transport protocol
│   ├── factory.py         # Transport factory
│   ├── http.py            # HTTP/HTTPS transport
│   ├── sse.py             # Server-Sent Events transport
│   └── stdio.py           # Standard I/O transport
├── fuzzer/                 # Fuzzing engine
│   ├── __init__.py
│   ├── tool_fuzzer.py     # Tool-level fuzzing
│   └── protocol_fuzzer.py # Protocol-level fuzzing
├── strategy/               # Fuzzing strategies
│   ├── __init__.py
│   ├── realistic/         # Realistic data generation
│   │   ├── __init__.py
│   │   ├── protocol_type_strategy.py
│   │   └── tool_strategy.py
│   ├── aggressive/        # Aggressive attack vectors
│   │   ├── __init__.py
│   │   ├── protocol_type_strategy.py
│   │   └── tool_strategy.py
│   └── strategy_manager.py # Strategy orchestration
├── safety_system/          # Safety and protection
│   ├── __init__.py
│   ├── safety.py          # Core safety logic
│   └── system_blocker.py  # System command blocking
├── auth/                   # Authentication providers
│   ├── __init__.py
│   ├── providers.py        # Auth provider implementations
│   ├── manager.py          # Auth management
│   └── loaders.py          # Configuration loading
├── client.py               # Unified MCP client
└── __main__.py            # Entry point for module execution
```

## 🔌 Component Details

### 1. CLI Layer

The CLI layer provides the user interface and handles argument parsing, validation, and execution flow.

**Key Components:**

- `args.py`: Defines and validates command-line arguments
- `main.py`: Main entry point that orchestrates the CLI
- `runner.py`: Executes the fuzzing logic based on parsed arguments

**Responsibilities:**

- Parse and validate user input
- Create appropriate transport instances
- Initialize the fuzzing client
- Handle errors and display results

### 2. Transport Layer

The transport layer abstracts communication with MCP servers, supporting multiple protocols.

**Key Components:**

- `base.py`: Abstract TransportProtocol class defining the interface
- `factory.py`: Factory function for creating transport instances
- `http.py`: HTTP/HTTPS transport implementation
- `sse.py`: Server-Sent Events transport implementation
- `stdio.py`: Standard I/O transport for local processes

**Transport Protocol Interface:**

```python
class TransportProtocol(ABC):
    async def send_request(self, method: str, params=None) -> Any
    async def send_raw(self, payload: Any) -> Any
    async def send_notification(self, method: str, params=None) -> None
    async def get_tools(self) -> List[Dict[str, Any]]
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any
```

### 3. Fuzzing Engine

The fuzzing engine orchestrates the testing process and manages test execution.

**Key Components:**

- `tool_fuzzer.py`: Tests individual tools with various argument combinations
- `protocol_fuzzer.py`: Tests MCP protocol types with various message structures

**Fuzzing Process:**

1. **Discovery**: Automatically discover available tools from the server
2. **Strategy Selection**: Choose appropriate fuzzing strategy (realistic vs aggressive)
3. **Data Generation**: Generate test data using Hypothesis and custom strategies
4. **Execution**: Execute tests and collect results
5. **Analysis**: Analyze results and generate reports

### 4. Strategy System

The strategy system generates test data using different approaches.

**Key Components:**

- `realistic/`: Generates valid, realistic data for functionality testing
- `aggressive/`: Generates malicious/malformed data for security testing
- `strategy_manager.py`: Orchestrates strategy selection and execution

**Strategy Types:**

- **Realistic Strategies**: Generate valid Base64, UUIDs, timestamps, semantic versions
- **Aggressive Strategies**: Generate SQL injection, XSS, path traversal, buffer overflow attempts

### 5. Safety System

The safety system provides multiple layers of protection against dangerous operations.

**Key Components:**

- `safety.py`: Core safety logic and filtering
- `system_blocker.py`: System command blocking and PATH shimming

**Safety Features:**

- **Environment Detection**: Automatically detects production systems
- **System Command Blocking**: Prevents execution of dangerous commands
- **Filesystem Sandboxing**: Confines file operations to specified directories
- **Process Isolation**: Safe subprocess handling with timeouts
- **Input Sanitization**: Filters potentially dangerous input

### 6. Authentication System

The authentication system manages various authentication methods for MCP servers.

**Key Components:**

- `providers.py`: Authentication provider implementations
- `manager.py`: Authentication management and coordination
- `loaders.py`: Configuration loading from files and environment

**Supported Auth Types:**

- **API Key authentication**
- **Basic username/password authentication**
- **OAuth token authentication**
- **Custom header authentication**

## 🔄 Execution Flow

### Tool Fuzzing Flow

```mermaid
sequenceDiagram
    participant CLI as CLI
    participant Client as Unified Client
    participant Transport as Transport
    participant Server as MCP Server
    participant Fuzzer as Tool Fuzzer
    participant Strategy as Strategy Manager

    CLI->>Client: Initialize with transport
    Client->>Transport: Create transport instance
    Transport->>Server: Discover available tools
    Server-->>Transport: Return tool list
    Transport-->>Client: Tool list received

    loop For each tool
        Client->>Fuzzer: Fuzz tool
        Fuzzer->>Strategy: Request test data
        Strategy-->>Fuzzer: Return test data

        loop For each test run
            Fuzzer->>Client: Execute tool call
            Client->>Transport: Send tool request
            Transport->>Server: Execute tool
            Server-->>Transport: Return result
            Transport-->>Client: Result received
            Client-->>Fuzzer: Tool result
            Fuzzer->>Fuzzer: Record result
        end
    end

    Fuzzer-->>Client: Fuzzing complete
    Client-->>CLI: Generate report
```

### Protocol Fuzzing Flow

```mermaid
sequenceDiagram
    participant CLI as CLI
    participant Client as Unified Client
    participant Transport as Transport
    participant Server as MCP Server
    participant Fuzzer as Protocol Fuzzer
    participant Strategy as Strategy Manager

    CLI->>Client: Initialize with transport
    Client->>Transport: Create transport instance

    loop For each protocol type
        Client->>Fuzzer: Fuzz protocol type
        Fuzzer->>Strategy: Request protocol messages
        Strategy-->>Fuzzer: Return test messages

        loop For each test run
            Fuzzer->>Client: Execute protocol message
            Client->>Transport: Send protocol message
            Transport->>Server: Execute protocol
            Server-->>Transport: Return response
            Transport-->>Client: Response received
            Client-->>Fuzzer: Protocol response
            Fuzzer->>Fuzzer: Record result
        end
    end

    Fuzzer-->>Client: Fuzzing complete
    Client-->>CLI: Generate report
```

## Design Principles

### 1. Separation of Concerns

Each component has a single, well-defined responsibility:

- **Transport Layer**: Handles communication protocols
- **Fuzzing Engine**: Manages test execution
- **Strategy System**: Generates test data
- **Safety System**: Provides protection mechanisms

### 2. Protocol Agnosticism

The fuzzer logic is completely independent of transport protocols:

- **Fuzzing strategies work** with any transport
- **New transports can be added** without changing fuzzer logic
- **Transport-specific details** are encapsulated

### 3. Extensibility

The system is designed for easy extension:

- **New transport protocols** can be added by implementing the interface
- **New fuzzing strategies** can be added to the strategy system
- **New safety features** can be added to the safety system

### 4. Safety First

Safety is built into every layer:

- **Environment detection** prevents dangerous operations
- **Input sanitization** filters potentially dangerous data
- **System command blocking** prevents command execution
- **Filesystem sandboxing** confines file operations

### 5. Testability

Each component can be tested independently:

- **Clear interfaces** between components
- **Dependency injection** for external dependencies
- **Comprehensive mocking** support
- **Isolated test environments**

## Configuration Management

### Environment Variables

The system uses environment variables for configuration:

```bash
# Core configuration
export MCP_FUZZER_TIMEOUT=30.0
export MCP_FUZZER_LOG_LEVEL=INFO
export MCP_FUZZER_SAFETY_ENABLED=true

# Transport configuration
export MCP_FUZZER_HTTP_TIMEOUT=30.0
export MCP_FUZZER_SSE_TIMEOUT=30.0
export MCP_FUZZER_STDIO_TIMEOUT=30.0

# Safety configuration
export MCP_FUZZER_FS_ROOT=~/.mcp_fuzzer
export MCP_FUZZER_ENABLE_SAFETY=true
export MCP_FUZZER_DANGEROUS_TESTS_DISABLED=false
```

## Performance Considerations

### Asynchronous Design

The system uses async/await throughout for better performance:

- **Non-blocking I/O operations**
- **Concurrent tool execution**
- **Efficient resource utilization**

### Resource Management

Careful resource management ensures stability:

- **Connection pooling** for HTTP transport
- **Process lifecycle management** for stdio transport
- **Memory-efficient data generation**
- **Timeout handling** for all operations

### Scalability

The architecture supports scaling:

- **Multiple worker processes**
- **Distributed fuzzing** across machines
- **Configurable concurrency limits**
- **Resource usage monitoring**

## 🔒 Security Considerations

### Input Validation

All input is validated and sanitized:

- **Argument validation** at CLI level
- **Transport-level input sanitization**
- **Safety system filtering**
- **Environment variable validation**

### Access Control

The system implements access control:

- **Filesystem sandboxing**
- **Process isolation**
- **System command blocking**
- **Environment detection**

### Audit Logging

Comprehensive logging for security:

- **All operations are logged**
- **Safety system actions are recorded**
- **Error conditions are tracked**
- **Performance metrics are collected**

## Monitoring and Observability

### Metrics Collection

The system collects various metrics:

- **Request success/failure rates**
- **Response times**
- **Error counts and types**
- **Resource usage**

### Logging

Comprehensive logging throughout:

- **Structured logging** with levels
- **Context-aware log messages**
- **Performance timing information**
- **Error stack traces**

### Health Checks

Built-in health monitoring:

- **Transport connectivity checks**
- **Server availability monitoring**
- **Safety system status**
- **Resource usage monitoring**
