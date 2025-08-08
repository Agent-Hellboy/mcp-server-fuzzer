# MCP Fuzzer Architecture - Mermaid Diagram

## Main Architecture Flow

```mermaid
graph TD
    A[User CLI<br/>__main__.py / cli.py] --> B[Unified Client<br/>client.py]
    B --> C[Tool Fuzzer<br/>fuzzer/tool_fuzzer.py]
    B --> D[Protocol Fuzzer<br/>fuzzer/protocol_fuzzer.py]

    C --> E[Strategy Manager<br/>strategy/strategy_manager.py]
    D --> E

    E --> G[Transport Layer<br/>transport.py]

    subgraph Safety
      SF[Safety Filter<br/>safety.py]
      SB[System Command Blocker<br/>system_blocker.py]
    end

    B -. start/stop .-> SB
    G -. sanitize/block .-> SF

    G --> H[HTTP Transport]
    G --> I[SSE Transport]
    G --> J[Stdio Transport]
    G --> K[WebSocket Transport]

    H --> M[MCP Server]
    I --> M
    J --> M
    K --> M

    M --> N[Results]
    N --> O[Rich Output Tables]

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff3e0
    style E fill:#e8f5e8
    style G fill:#fce4ec
    style SF fill:#ffe0e0
    style SB fill:#ffe0e0
    style O fill:#e8f5e8
```

## Detailed Component Breakdown

```mermaid
graph LR
    subgraph "Client Layer"
        A[__main__.py / cli.py<br/>CLI Entry Point]
        B[client.py<br/>Unified Orchestration]
    end

    subgraph "Fuzzer Orchestration"
        C[tool_fuzzer.py<br/>Tool Fuzzing Logic]
        D[protocol_fuzzer.py<br/>Protocol Fuzzing Logic]
    end

    subgraph "Strategy Data Generation"
        E[strategy_manager.py<br/>Dispatch (realistic/aggressive)]
        ER[realistic/*]
        EA[aggressive/*]
    end

    subgraph "Safety"
        SF[safety.py<br/>Argument-level safety]
        SB[system_blocker.py<br/>System-level blocking]
    end

    subgraph "Transport Layer"
        G[transport.py<br/>Abstract Transport]
        H[HTTPTransport]
        I[SSETransport]
        J[StdioTransport]
        K[WebSocketTransport]
    end

    A --> B
    B --> C
    B --> D
    C --> E
    D --> E
    E --> ER
    E --> EA
    E --> G
    G --> SF
    B --> SB
    G --> H
    G --> I
    G --> J
    G --> K
```

## Data Flow Sequence

```mermaid
sequenceDiagram
    participant U as User CLI
    participant C as Client
    participant SB as System Blocker
    participant SF as Safety Filter
    participant TF as Tool Fuzzer
    participant PF as Protocol Fuzzer
    participant SM as Strategy Manager
    participant T as Transport
    participant S as MCP Server

    U->>C: Parse args & create transport
    C->>SB: start_system_blocking()

    alt Tool Fuzzing Mode
        C->>T: tools/list
        T->>S: JSON-RPC request
        S-->>T: Tools list
        T-->>C: Tools list

        loop For each tool
            C->>TF: fuzz_tool
            TF->>SM: generate args (phase)
            SM-->>TF: fuzzed args
            C->>SF: is_safe_tool_call / sanitize_tool_call
            SF-->>C: safe args or safety response
            C->>T: tools/call
            T->>S: JSON-RPC request
            S-->>T: Response
            T-->>C: Response
        end
    else Protocol Fuzzing Mode
        C->>PF: fuzz_protocol_types
        PF->>SM: generate protocol messages (phase)
        SM-->>PF: fuzz data
        C->>T: send_request
        T->>S: JSON-RPC request
        S-->>T: Response
        T-->>C: Response
    end

    C->>SB: stop_system_blocking()
    C->>U: Display rich results & blocked-ops summary
```

## Custom Transport Integration

```mermaid
graph TD
    A[Your Custom Transport] --> B[TransportProtocol Interface]
    B --> C[send_request method]
    C --> D[MCP Server]

    subgraph "Custom Transport Examples"
        E[gRPC Transport]
        F[Redis Transport]
        G[Webhook Transport]
    end

    E --> B
    F --> B
    G --> B

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
```

## Key Benefits Visualization

```mermaid
mindmap
  root((MCP Fuzzer))
    Modular Design
      Clear separation
      Orchestration vs Data Gen
      Independent components
    Transport Agnostic
      Protocol independent
      Custom transports
      Plug-and-play
    Extensible
      New protocols
      New strategies
      New transports
    Testable
      Unit tests
      Mock transports
      Independent testing
    Rich Output
      Beautiful tables
      Detailed statistics
      Colorized results
```

## Usage Modes

```mermaid
graph LR
    A[User Input] --> B{mode?}
    B -->|tools| C[Tool Fuzzing]
    B -->|protocol| D[Protocol Fuzzing]
    B -->|both| E[Both Modes]

    C --> F[Fuzz tool arguments]
    D --> G[Fuzz protocol messages]
    E --> H[Fuzz both]

    F --> I[Rich Results]
    G --> I
    H --> I

    style A fill:#e1f5fe
    style I fill:#e8f5e8
```
