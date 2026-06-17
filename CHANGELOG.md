# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.6]

### Added

- Server-crash detection: a stdio server that dies mid-request (crash signal
  SIGSEGV/SIGABRT/... or a positive non-zero exit, distinct from the fuzzer's
  own SIGKILL/SIGTERM) is classified as a new `crashed` outcome via
  `ServerCrashError`, capturing the exit code/signal and a tail of the server's
  stderr (panic trace / ASan report). Per-crash reproduction files are written
  to `<output_dir>/crashes/`.
- Post-run findings analyzer (`mcp_fuzzer/analysis`) that classifies a broad set
  of MCP-server issue classes from the collected run data, written to
  `<output_dir>/findings.json` and summarized by category on stdout:
  - `crash`, `oversized_response` (resource exhaustion), `hang` (timeout)
  - `internal_error` (JSON-RPC -32603 / unhandled server exception)
  - `error_leakage` (stack trace / panic / sanitizer report in output)
  - `injection_reflection` (dangerous input token echoed back verbatim)
  - `performance_outlier` (response time far above the per-target median)
  - `non_determinism` (identical input producing differing outcomes)
- `OversizedResponseError` for responses exceeding the stdio read cap.

### Roadmap (not yet implemented)

- Auth-bypass detection (needs paired authed/unauthed request orchestration)
- Memory-growth/leak sampling (needs per-run RSS series plumbing)

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
