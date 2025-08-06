# MCP Fuzzer Architecture - Mermaid Diagram

## Main Architecture Flow

```mermaid
graph TD
    A[User CLI<br/>__main__.py] --> B[Unified Client<br/>client.py]
    B --> C[Tool Fuzzer<br/>fuzzer/tool_fuzzer.py]
    B --> D[Protocol Fuzzer<br/>fuzzer/protocol_fuzzer.py]

    C --> E[Tool Strategies<br/>strategy/tool_strategies.py]
    D --> F[Protocol Strategies<br/>strategy/protocol_strategies.py]

    E --> G[Transport Layer<br/>transport.py]
    F --> G

    G --> H[HTTP Transport]
    G --> I[SSE Transport]
    G --> J[Stdio Transport]
    G --> K[WebSocket Transport]
    G --> L[Custom Transport]

    H --> M[MCP Server]
    I --> M
    J --> M
    K --> M
    L --> M

    M --> N[Results]
    N --> O[Rich Output Tables]

    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#e8f5e8
    style D fill:#fff3e0
    style E fill:#e8f5e8
    style F fill:#fff3e0
    style G fill:#fce4ec
    style O fill:#e8f5e8
```

## Detailed Component Breakdown

```mermaid
graph LR
    subgraph "Client Layer"
        A[__main__.py<br/>CLI Entry Point]
        B[client.py<br/>Unified Orchestration]
    end

    subgraph "Fuzzer Orchestration"
        C[tool_fuzzer.py<br/>Tool Fuzzing Logic]
        D[protocol_fuzzer.py<br/>Protocol Fuzzing Logic]
    end

    subgraph "Strategy Data Generation"
        E[tool_strategies.py<br/>Tool Argument Generation]
        F[protocol_strategies.py<br/>Protocol Message Generation]
    end

    subgraph "Transport Layer"
        G[transport.py<br/>Abstract Transport]
        H[HTTPTransport]
        I[SSETransport]
        J[StdioTransport]
        K[WebSocketTransport]
        L[Custom Transports]
    end

    A --> B
    B --> C
    B --> D
    C --> E
    D --> F
    E --> G
    F --> G
    G --> H
    G --> I
    G --> J
    G --> K
    G --> L
```

## Data Flow Sequence

```mermaid
sequenceDiagram
    participant U as User CLI
    participant C as Client
    participant TF as Tool Fuzzer
    participant PF as Protocol Fuzzer
    participant TS as Tool Strategies
    participant PS as Protocol Strategies
    participant T as Transport
    participant S as MCP Server

    U->>C: Parse args & create transport
    C->>T: Initialize transport

    alt Tool Fuzzing Mode
        C->>T: Get tools list
        T->>S: JSON-RPC request
        S-->>T: Tools list
        T-->>C: Tools list

        loop For each tool
            C->>TF: Fuzz tool
            TF->>TS: Generate fuzz args
            TS-->>TF: Random/edge-case args
            TF->>C: Fuzz data
            C->>T: Call tool with args
            T->>S: JSON-RPC request
            S-->>T: Response
            T-->>C: Response
        end
    else Protocol Fuzzing Mode
        C->>PF: Fuzz protocol types
        PF->>PS: Generate protocol messages
        PS-->>PF: Fuzz data
        PF->>C: Protocol fuzz data
        C->>T: Send protocol request
        T->>S: JSON-RPC request
        S-->>T: Response
        T-->>C: Response
    end

    C->>U: Display rich results table
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
