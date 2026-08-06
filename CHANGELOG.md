# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Reorganized the README and documentation around installation, supported MCP
  versions, fuzzing workflows, findings, safety, runtime monitoring, and CI.
- Added release, CI, Codecov, PyPI, Docker, Python, license, and MCP support
  badges to the README.
- Removed implementation-focused detail from the primary user guides while
  keeping architecture and contributor references available separately.

### Added

- First-class runtime-probe CLI and config options for enabling
  `mcpfz-probe`, selecting the backend/binary, setting workspace/tmp policy
  roots, and allowlisting expected exec or network destinations. Environment
  variables remain supported as fallbacks, and the runtime probe remains
  disabled by default.
- Runtime-probe capability preflight for `ebpf`/`auto`, warnings for non-stdio
  transports, expanded runtime finding categories from `mcpfz-probe`, and OWASP
  MCP Top 10 IDs/URLs on runtime findings.
- Additional MCP server-audit checks for ANSI terminal escape sequences,
  trigger/conversation-history conditioned tool metadata, divergent duplicate
  tool definitions, and canonical tool-definition hashes plus OWASP MCP
  IDs/URLs in evidence.

## [0.5.0] - 2026-07-22

### Added

- MCP `2026-07-28` release-candidate support behind the existing
  `--spec-schema-version` / `spec_schema_version` / `MCP_SPEC_SCHEMA_VERSION`
  configuration path:
  - `2026-07-28` resolves to the concrete vendored schema when present, with a
    draft-schema fallback for older checkouts.
  - Streamable HTTP requests for `2026-07-28` include per-request
    `io.modelcontextprotocol/*` `_meta` fields and routing headers
    (`MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` where applicable).
  - Spec guard uses `server/discover` for stateless MCP revisions instead of the
    older `initialize` / `notifications/initialized` handshake.
- Additional server security-audit checks for hidden prompt-injection content in
  MCP tool metadata and schemas, including invisible Unicode controls, hidden
  HTML/block/fenced instruction payloads, and base64-encoded poisoning payloads.

### Changed

- Updated the vendored MCP spec submodule so concrete dated schemas are bundled
  through `2026-07-28`.
- Expanded tool-poisoning detection patterns and dangerous capability-combination
  evidence reported by `--security-audit`.
- Documented `2026-07-28` as a supported protocol/schema version override in CLI
  help and configuration docs.

## [0.4.3] - 2026-07-05

### Added

- `mcpfz-probe` optional-dependency extra: `pip install "mcp-fuzzer[mcpfz-probe]"`
  installs the runtime monitor package.

## [0.4.2] - 2026-07-04

### Added

- Opt-in runtime-probe integration with
  [mcpfz-probe](https://github.com/Agent-Hellboy/mcpfz-probe): scope the sidecar
  to the stdio server's process group, mark begin/end around each tool call, and
  merge kernel-observed runtime findings (`runtime.exec`, `runtime.net_connect`,
  `runtime.sensitive_read`, `runtime.fs_write`, `runtime.fs_delete`,
  `runtime.fs_chmod`, `runtime.ptrace`) into the report. Enabled via
  `MCP_FUZZER_RUNTIME_PROBE`; a no-op when unset. See the README
  "Runtime monitoring" section.

## [0.4.0] - 2026-06-18

### Added

- SOLID session architecture: top-level `orchestrator/` drives fuzz → diagnostics
  audits → persist (`findings.json`, crash repros); `cli/app.py` is the
  composition root with `SessionBootstrap` and `PostRunPresenter`
- `ARCHITECTURE.md` documenting layer rules, session flow, and structural
  conventions; `tests/unit/test_layer_imports.py` guards L2 import boundaries
- Paper-backed MCP security diagnostics in `mcp_fuzzer/diagnostics/`, run
  post-fuzz by the orchestrator. Each finding family stamps `paper_arxiv_id`,
  `paper_url`, and `paper_title` in `evidence`; `findings.json` and the stdout
  summary link back to the source paper:
  - [*A First Measurement Study on Authentication Security in Real-World Remote
    MCP Servers*](https://arxiv.org/abs/2605.22333) — OAuth flaw types F1–F9
    (`--auth-audit`, `--auth-audit-intrusive`): RFC 9728/8414 metadata review,
    authorization-endpoint probes (PKCE downgrade, blind client trust, weak
    state, consent-page heuristic), unauthenticated tool exposure when OAuth is
    advertised, and opt-in intrusive DCR / open-redirect probes (F1, F7)
  - [*MCP Safety Audit: LLMs with the Model Context Protocol*](https://arxiv.org/abs/2503.23278)
    — tool/schema poisoning markers, cross-tool shadowing, and output prompt-
    injection oracles on fuzz runs (`--security-audit`)
  - [*Uncovering MCP Security Vulnerabilities in AI Agent Ecosystems*](https://arxiv.org/abs/2509.06572)
    — dangerous capability combinations (local-read plus network-egress tools on
    the same server) (`--security-audit`)
  - [*MCPSecBench: A Benchmark for MCP Server Security*](https://arxiv.org/abs/2508.13220)
    — cleartext / non-TLS transport detection for remote endpoints
    (`--security-audit`)
  - Active injection oracles on collected tool-run output (command, path traversal,
    SQL, echoed prompt-injection markers) are also surfaced under
    `--security-audit`, primarily aligned with MCPSecBench and the MCP Safety
    Audit poisoning taxonomy above
  - Auth and server audit phases never abort the fuzz pass; skipped or errored
    runs log a reason instead of reporting a clean result

### Changed

- Rename `findings/` → `diagnostics/`; flatten nested packages across `cli/`,
  `client/`, `config/`, `fuzz_engine/`, `reports/`, `transport/`, and
  `safety_system/`
- Relocate root helpers into layer homes (no compatibility shims): `corpus` →
  `fuzz_engine/`, `env` → `config/`, `outcomes` and container `healthcheck` →
  `client/`, `spec_version` and tool schema helpers → `spec_guard/`; merge
  `extract_tool_runs` into `types.py` and remove `utils/`
- Docker healthcheck entrypoint: `python -m mcp_fuzzer.client.healthcheck`
- Merge `ClientSettings` into `SessionSettings`; remove reporter/orchestrator
  compatibility shims and duplicate settings types
- Split god-modules (`protocol_client`, `tool_client`, `diagnostics/server`,
  `auth_oauth`, `spec_checks`, `FuzzerReporter`) and move execution pipeline
  to `orchestrator/pipeline.py`

## [0.3.6] - 2026-06-17

### Added

- Server-crash detection: a stdio server that dies mid-request (crash signal
  SIGSEGV/SIGABRT/... or a positive non-zero exit, distinct from the fuzzer's
  own SIGKILL/SIGTERM) is classified as a new `crashed` outcome via
  `ServerCrashError`, capturing the exit code/signal and a tail of the server's
  stderr (panic trace / ASan report). Per-crash reproduction files are written
  to `<output_dir>/crashes/`.
- Post-run findings analyzer (`mcp_fuzzer/diagnostics/`) that classifies a broad set
  of MCP-server issue classes from the collected run data, written to
  `<output_dir>/findings.json` and summarized by category on stdout:
  - `crash`, `oversized_response` (resource exhaustion), `hang` (timeout)
  - `internal_error` (JSON-RPC -32603 / unhandled server exception)
  - `error_leakage` (stack trace / panic / sanitizer report in output)
  - `injection_reflection` (dangerous input token echoed back verbatim)
  - `performance_outlier` (response time far above the per-target median)
  - `non_determinism` (identical input producing differing outcomes)
  - `memory_growth` (server RSS grows multi-fold across runs of a stdio target,
    sampled via psutil)
  - `auth_bypass` (a protected tool answers an unauthenticated call when auth is
    configured) -- an active probe that issues unauthenticated calls
- `OversizedResponseError` for responses exceeding the stdio read cap.

## [0.3.5] - 2026-06-17

### Added

- MCP 2025-11-25 client-side OAuth 2.1 authorization (`mcp_fuzzer/auth/oauth/`):
  - Protected Resource Metadata discovery (RFC 9728) and Authorization Server
    Metadata discovery (RFC 8414 / OpenID Connect), fetching the documents and
    extracting the authorization server, endpoints, and PKCE capability
  - Authorization Code grant with mandatory PKCE (S256) and a loopback redirect
    server to capture the callback, plus `state` CSRF validation
  - `client_credentials` grant for unattended machine-to-machine fuzzing
  - Client registration: pre-registered client, Client ID Metadata Documents,
    and Dynamic Client Registration (RFC 7591), selected per spec priority
  - Resource Indicators (RFC 8707): canonical `resource` parameter on every
    authorization and token request, with refresh-token support
  - On-disk token cache (owner-only perms) so the browser authorization step
    happens at most once; the URL is printed instead of auto-opening a browser
    by default (opt in with `--oauth-open-browser`)
  - CLI flags: `--oauth`, `--oauth-grant`, `--oauth-client-id`,
    `--oauth-client-secret`, `--oauth-scope`, `--oauth-client-id-metadata-url`,
    `--oauth-open-browser`, `--oauth-no-token-cache`
- `--fail-if-no-tools` to exit non-zero (code 2) when no tools could be fuzzed (auth required, unreachable endpoint, or no tools exposed), so CI/registry sweeps don't misread "no tools available" as success
- Stdout summary now prints a clear `Status: BLOCKED — no tools available` vs `Status: completed — N tool(s) fuzzed` line
- Tool summary breaks outcomes into server-rejected input vs accepted-malformed findings vs transport/protocol anomalies, so server-side input validation isn't conflated with fuzzer/transport faults

### Fixed

- Serialize stdio request/response exchanges behind a per-event-loop I/O lock so bounded-concurrency fuzz runs no longer crash with "readuntil() called while another coroutine is already waiting for incoming data"
- Normalize single-tool results to `{tool_name: {runs: [...]}}` so tools-mode reports populate `tools_tested` and per-run outcomes
- Skip empty Protocol Results and Spec Guard sections when the active mode does not produce that data
- Always emit a plain-text summary to stdout (including piped/CI stdout), not only Rich TTY output
- Sweep all default protocol types when `--mode protocol` is used without `--protocol-type`
- Fall back to method-based fuzz builders for protocol types without bundled schema (realistic and aggressive phases)
- Treat server rejection of malformed input as success and accepted malformed input as a finding
- Accept all bundled MCP schema versions (`2025-11-25`, `2025-06-18`, etc.) via data-driven discovery
- Print `mcp-fuzzer vX.Y.Z` from `--version` via explicit argparse `prog`
- Add `--seed` for reproducible fuzz payload generation threaded through mutators
- List real auth environment variable names in the startup panel
- Validate `tool_mapping` and `default_provider` references in auth config and raise `AuthConfigError` on typos
- Stop counting safety-blocked runs as exceptions in executor metrics
- Account for invariant violations in protocol success in `result_builder`
- Pass the injected RNG into `mutate_seed_payload` on reseed paths
- Always restore required JSON-RPC envelope keys on protocol reseed
- Remove duplicate spec-check aggregation in `run_plan`
- Use categorical `ErrorType` for tool setup failures instead of raw exception strings
- Drain stdio transport stderr in a background task to prevent pipe deadlocks
- Escape Markdown exception cells to prevent table injection
- Neutralize CSV formula-injection prefixes in cell values
- Create nested `--output-dir` paths with `parents=True`
- Add async context manager, idempotent shutdown, and post-shutdown guard to `AsyncFuzzExecutor`
- Key executor semaphores to the running event loop
- Thread seeded RNG through `rng_context`, `schema_parser`, and tool/protocol strategies
- Handle contradictory `allOf` schemas explicitly (empty type/enum intersection)
- Intersect `allOf` enum values across branches
- Emit required object properties even when missing from `properties`
- Honor `--max-concurrency` with bounded `asyncio.gather` in tool and protocol clients
- Include `safety_blocked` and `safety_sanitized` on protocol mutation-failure results
- Guard `SIGQUIT` handler registration on platforms without it
- Wire YAML `auth` section through `resolve_auth_port` and `yaml_loader`
- Accept `mappings` as an alias for `tool_mapping` in auth config and schema
- Add `https` to CLI `--protocol` choices to match config schema
- Validate environment CHOICE variables case-sensitively
- Default `--output-dir` to `None` and merge nested `output.directory` from config
- Keep configured OAuth `token_type` instead of overwriting from token response
- Reject non-object JSON auth config with `AuthConfigError`
- Tally blocked commands using `COMMAND` in danger summaries
- Sanitize subprocess environment in `ProcessLifecycle.start`
- Catch `LimitOverrunError` in stdio `ProcessSupervisor.read_with_cap`
- Print default command-block shim message to stderr only
- Follow HTTP 301/302/303 redirects in streamable HTTP and HTTP transports
- Allow cross-origin redirects when the redirect target passes network host policy
- Log expected transport failures during tools/list without full tracebacks
