# Design Pattern Review

This document explains how the MCP Server Fuzzer applies common design
patterns, how well they fit the current implementation, and where future
contributors can improve the architecture. Each section lists the primary
patterns in play, a qualitative "fit score" (0-10), and concrete next steps.

## Pattern Map

| Module | Primary Patterns | Fit Score |
| --- | --- | --- |
| CLI & Config | Facade, Builder, Port/Adapter | 8 |
| Client Orchestration | Facade, Mediator | 8 |
| Transport Layer | Strategy, Adapter, Factory/Registry, State | 9 |
| Mutators & Strategies | Strategy, Prototype, Object Pool | 8 |
| Execution & Concurrency | Executor, Builder | 7 |
| Safety System | Strategy, Policy, Adapter | 7 |
| Runtime & Process Management | State, Observer, Strategy, Watchdog, Builder | 8 |
| Reporting & Output | Builder, Strategy, Adapter | 7 |

## Module-by-Module Analysis

### CLI & Config (Fit Score: 8/10)

- **Patterns Used:** Facade (`mcp_fuzzer/cli/entrypoint.py` `run_cli` and
  `mcp_fuzzer/client/main.py` `unified_client_main`) as the single entry point
  that wires parsing, validation, safety, transport, and execution. Builder
  (`mcp_fuzzer/fuzz_engine/runtime/config.py` `ProcessConfigBuilder`) for
  composing process configs. Port/Adapter (Hexagonal) for config access
  (`mcp_fuzzer/client/ports/config_port.py` + `mcp_fuzzer/client/adapters/config_adapter.py`).
- **Strengths:** Clear top-level flow: parse → validate → merge config → execute.
  Config access is mediated through a port, so core components avoid direct
  coupling to config storage.
- **Notes:** CLI orchestration is covered by unit tests, and command-style
  run steps are encapsulated in the runtime run plan.

### Client Orchestration (Fit Score: 8/10)

- **Patterns Used:** Facade (`mcp_fuzzer/client/base.py` `MCPFuzzerClient`) exposes
  a unified API for tool/protocol fuzzing and reporting. Mediator-style
  coordination happens in `MCPFuzzerClient` and `unified_client_main`, which
  orchestrate `ToolClient`, `ProtocolClient`, `SafetyFilter`, and `FuzzerReporter`
  without those components knowing about each other.
- **Strengths:** The client layer is the single high-level surface area for
  fuzzing operations, keeping CLI and tests simple.
- **Notes:** Mode handling is consolidated via a run plan and execution pipeline.

### Transport Layer (Fit Score: 9/10)

- **Patterns Used:** Strategy via `TransportDriver` with concrete drivers
  (`HttpDriver`, `SseDriver`, `StdioDriver`, `StreamHttpDriver`). Adapter
  via `JsonRpcAdapter` to normalize RPC helpers across transports.
  Factory/Registry via `DriverCatalog` + `build_driver` in
  `mcp_fuzzer/transport/catalog`. State via `DriverState` and `LifecycleBehavior`.
- **Strengths:** Registry-driven construction makes it easy to add custom
  transports. Mixins (`HttpClientBehavior`, `ResponseParserBehavior`,
  `LifecycleBehavior`) remove duplication while keeping drivers focused.
- **Notes:** Retry policy can be layered via `RetryingTransport`; transport docs
  now cover registry and adapter expectations.

### Mutators & Strategies (Fit Score: 8/10)

- **Patterns Used:** Strategy (`ToolStrategies`, `ProtocolStrategies`) for
  switching realistic/aggressive generators. Prototype via `SeedPool` +
  `mutate_seed_payload`, which clone and mutate high-value inputs. Object Pool
  in `SeedPool`, maintaining a bounded pool of reusable seeds.
- **Strengths:** Phase-based strategies keep fuzzing logic testable and
  extensible. Seed pooling introduces feedback-guided fuzzing without complex
  dependencies.
- **Notes:** Strategy overrides can be registered at runtime via
  `strategy_registry`, with documented extension examples.

### Execution & Concurrency (Fit Score: 7/10)

- **Patterns Used:** Executor (`AsyncFuzzExecutor`) encapsulates concurrency and
  scheduling. Builder (`ResultBuilder`) standardizes output shape for tool,
  protocol, and batch runs.
- **Strengths:** Executors isolate concurrency concerns; builders make results
  consistent across clients and reporters.
- **Notes:** A shared execution pipeline (`ClientExecutionPipeline`) coordinates
  tool/protocol runs from a single interface.

### Safety System (Fit Score: 7/10)

- **Patterns Used:** Strategy via `DangerDetector` and policy helpers in
  `mcp_fuzzer/safety_system/policy.py`. Adapter via `SandboxProvider` to swap
  filesystem sandbox implementations. The `SafetyFilter` acts as the main
  policy engine with pluggable components.
- **Strengths:** Detection and sanitization are separated, making it easier to
  extend or replace detection rules.
- **Notes:** Safety documentation now includes extension points and a minimal
  policy configuration example.

### Runtime & Process Management (Fit Score: 8/10)

- **Patterns Used:** State (`ProcessState`, `DriverState`) for lifecycle
  tracking. Observer (`ProcessEventObserver`) for runtime and transport event
  hooks. Strategy (`ProcessSignalStrategy`, `TerminationStrategy`) for
  pluggable signal handling. Watchdog (`ProcessWatchdog`) for hang detection.
  Builder (`ProcessConfigBuilder`) for composing process configs.
- **Strengths:** The watchdog + registry split keeps process supervision
  testable and decoupled from transports.
- **Notes:** Process lifecycle transitions are documented in the process
  management guide.

### Reporting & Observability (Fit Score: 7/10)

- **Patterns Used:** Builder (`OutputProtocol`, `ResultBuilder`) for standardized
  report payloads. Strategy-like formatter set (`ConsoleFormatter`,
  `JSONFormatter`, `TextFormatter`, etc.). Adapter (`ReportFormatter` Protocol)
  defines a common formatter contract.
- **Strengths:** OutputProtocol centralizes format semantics; formatters are
  small and focused.
- **Notes:** Formatter selection now goes through a registry, and the
  OutputProtocol schema is documented for external tooling.

Maintaining this review ensures new contributors can map their work to the
existing architecture while spotting opportunities for better abstractions.
