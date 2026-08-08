# Session memory

## 2026-08-08 - Complete remaining black-box security checks

- Branch: `finish-mcp-security-audit-checks`
- Goal: Fold the remaining feasible MCP security-audit roadmap items into the
  fuzzer and remove the temporary roadmap.
- Changed: Added tool-name squatting detection, opt-in foreign-Origin probing,
  CLI/config wiring, unit tests, README and guide updates, and changelog
  entries. Removed `MCP_SECURITY_AUDIT_ROADMAP.md`.
- Research: OWASP MCP03/MCP05 guidance and the MCP Streamable HTTP transport
  requirement that invalid Origin values receive HTTP 403.
- Validation: `tox -e ruff`; focused diagnostics, CLI, and orchestrator tests
  passed (109 tests).
- Notes: Token passthrough/confused-deputy behavior remains outside this
  black-box client's reliable evidence boundary; it cannot be confirmed
  without observing a downstream service or server internals.
- Next: Consider a separately authorized multi-server or downstream-observer
  mode if token passthrough needs measurable coverage.

## 2026-08-08 - Make intrusive Origin audit version-aware

- Branch: `finish-mcp-security-audit-checks`
- Changed: The Origin/DNS-rebinding probe now sends legacy `initialize` for
  `2025-11-25` and earlier revisions, but uses stateless `server/discover`,
  `MCP-Protocol-Version`, `Mcp-Method`, and per-request `_meta` for
  `2026-07-28`. The orchestrator passes the selected schema version through to
  the probe.
- Changed: Renamed stale release-candidate schema constants, updated the
  released-version changelog wording, corrected Docker Compose defaults to
  `2025-11-25`, and added protocol-version rules to `AGENTS.md`.
- Validation: `tox -e ruff` and the focused diagnostics/orchestrator/spec-guard/
  transport suite passed (96 tests); the earlier full unit suites also passed
  in both randomized and deterministic order before this compatibility patch.
- Research: Official MCP sources confirm `2026-07-28` is the released latest
  revision; `2025-11-25` remains the prior revision and the compatibility
  baseline.
