# Fuzzer Design

This page documents how MCP Server Fuzzer is structured and why it makes the
choices it does. It focuses on the control flow, data flow, and the boundaries
between components.

## Design goals

- Schema-first: always respect MCP JSON Schema while still exploring edges.
- Two-phase fuzzing: realistic for conformance, aggressive for robustness.
- Safety-first: gate risky actions, constrain filesystem/network access, and
  report blocked operations without mutating the dangerous payloads being fuzzed.
- Deterministic where useful: cycle boundaries and enums for repeatability.
- Feedback-aware: reuse interesting inputs without instrumentation.

## Core components

- **Clients**: drive protocol/tool fuzzing runs and manage concurrency.
- **Mutators**: generate or mutate inputs per phase (realistic/aggressive).
- **Strategies**: schema-aware generators and semantic payload pickers.
- **Seed Pool**: stores interesting inputs, deduplicates by signature, reuses.
- **Safety System**: filters risky operations and produces safety reports.
- **Reporting**: aggregates outcomes into JSON/CSV/HTML/Markdown outputs.

## High-level flow

```mermaid
graph TD
    CLI[CLI / Config] --> Client[Client Runner]
    Client --> Mutator[Protocol/Tool Mutator]
    Mutator --> Strategy[Schema Strategy]
    Mutator --> SeedPool[Seed Pool]
    Strategy --> Payloads[Payload + Boundary Gen]
    Mutator --> Request[Build Request]
    Request --> Transport[Transport (HTTP/SSE/STDIO/StreamableHTTP)]
    Transport --> Target[MCP Server]
    Target --> Response[Response]
    Response --> Checks[Spec Checks + Response Signatures]
    Checks --> Feedback[Signatures / Feedback]
    Feedback --> SeedPool
    Response --> Reports[Reports]
```

## Phases

### Realistic phase

- Generates strictly schema-valid values.
- Cycles boundary values (min/max/mid) and enum values deterministically.
- Prioritizes conformance and stable baselines.

### Aggressive phase

- Injects adversarial payloads (SQL, XSS, path traversal, etc.).
- Attempts off-by-one and type confusion cases.
- Still respects length and structural constraints when possible.

## Feedback loop

- Responses are summarized into **signatures** (error type, spec failures,
  response shape).
- Signatures deduplicate stored seeds and prioritize interesting inputs.
- Mutators re-seed using these stored inputs to explore new variations.

## Determinism and reproducibility

- Realistic generators use run index cycling for boundary coverage.
- Seed pools use an internal RNG to keep mutation decisions testable.
- Persisted corpus directories make runs replayable across sessions.

## Safety considerations

- Safety checks run before execution for tool/path sanitization, protocol
  blocking hooks, command blocking, and network policy enforcement.
- Fuzz payloads containing dangerous strings are generally preserved as test
  inputs; the default safety filter mainly sanitizes filesystem paths.
- After execution, the system records spec-check results, response signatures,
  and blocked-operation reports for auditability and feedback-guided reseeding.

## Design trade-offs

- No instrumentation-based coverage: simplifies deployment and keeps the tool
  usable against remote servers.
- Schema-first generation: better for MCP conformance but may miss
  implementation-specific hidden paths (mitigated via aggressive phase).
