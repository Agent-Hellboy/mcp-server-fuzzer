# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.5]

### Fixed

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
