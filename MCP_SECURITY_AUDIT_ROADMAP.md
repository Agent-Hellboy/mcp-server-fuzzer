# MCP Security Audit Expansion — Roadmap & Progress

> Working/continuation doc. Tracks the effort to mine MCP-security research papers,
> derive black-box fuzzer checks, ship them in PR(s), and cut release **0.4.0**.
> Not a permanent doc — fold the useful parts into real docs before release and
> delete this. Keep it updated at the end of every work session.

Last updated: 2026-06-18

---

## Objective

1. Find **10–20 research papers/reports** on MCP (Model Context Protocol) security.
2. Extract their **attack vectors / vulnerability taxonomies**.
3. For each vector, decide if it is **black-box checkable by a server fuzzer** and,
   if so, **how** (what to send, what response signature flags it).
4. **Implement** the feasible checks as new analysis modules + CLI flags + tests + docs,
   in the same spirit as the existing OAuth `auth_audit.py` (F1–F9).
5. Cut a **major release 0.4.0** once the new checks are merged.

The model to mirror: PR #174 "Add MCP OAuth auth-security audit checks" (merged
2026-06-17, merge commit `c80cadd`), which mapped the F1–F9 flaws from
arXiv 2605.22333 onto black-box probes.

---

## Phase status

- [x] **Phase 0 — Reference impl landed.** PR #174 merged (OAuth F1–F9 audit, `--auth-audit` / `--auth-audit-intrusive`). This is the template.
- [~] **Phase 1 — Research (IN PROGRESS).** deep-research workflow running in background.
  - Task ID: `w57bc844n` · Run ID: `wf_2717f333-3e1`
  - Output: paste/synthesize into **§ Research findings** below when it completes.
- [~] **Phase 2 — Design.** Turn probeable vectors into a checks taxonomy (IDs, severity, detection method). Get scope sign-off from user. Fill **§ Proposed checks**.
- [~] **Phase 3 — Implement (IN PROGRESS).** Branch `mcp-tool-security-checks`, uncommitted. Checks live in flat `mcp_fuzzer/diagnostics/` (server checks in `server.py` + `server_*` modules), driven by top-level `mcp_fuzzer/orchestrator/`. `--security-audit` CLI wired. Deferred: name squatting (#10), origin/rebinding (#11), token passthrough (#12).
  - **Structure cleanup done:** flat `diagnostics/` library + top-level `orchestrator/` (run plan, audit registry, persist). Full suite green both orderings.
  - **Orchestrator owns the session spine:** `orchestrator/run_plan.py` executes fuzz; `cli/app.py` is thin bootstrap → `run_session` → `PostRunPresenter`.
- [ ] **Phase 4 — Release 0.4.0.** CHANGELOG dated section, version bump, Testing Check, tag + push.

---

## Scope decisions (resolve in Phase 2)

- **Server-side vs client-side.** The fuzzer is a *black-box server* prober
  (connects to a running MCP server over stdio/HTTP/SSE). These fit cleanly:
  tool-description/metadata poisoning, injection-in-params, schema
  over-permissiveness, resource exhaustion/DoS, auth/OAuth, session/transport.
  Vectors where a *malicious server attacks a client* need a new "client-side
  audit" angle — flag explicitly which (if any) to include in 0.4.0 vs defer.
- **One big PR vs grouped PRs.** Lean toward grouped-by-theme PRs (e.g.
  "tool-poisoning checks", "injection checks", "transport/session checks") so
  review + codecov stay tractable; confirm with user.
- **New CLI surface.** Likely a generic `--security-audit` umbrella or
  per-family flags. Decide naming so it composes with existing `--auth-audit`.

---

## Reference implementation anatomy (so new checks plug in the same way)

The OAuth audit added one module + wired it into ~6 places. New check families
follow the identical wiring. Files and what each does:

| Path | Role |
|------|------|
| `mcp_fuzzer/diagnostics/` | `Finding` model, `classify_fuzz_runs()`, auth + server audit probes |
| `mcp_fuzzer/orchestrator/` | Post-fuzz pipeline: run plan, audit registry, persist `findings.json` |
| `mcp_fuzzer/cli/parser_audit.py` | Add `--<flag>` `action="store_true"` with help text citing the paper. |
| `mcp_fuzzer/cli/config_merge.py` | Add `("<flag>", "<flag>")` to the `_transfer_config_to_args` mapping AND to the `merged` dict in `build_cli_config`. (Both! PR #174 review caught the mapping miss.) |
| `mcp_fuzzer/cli/validators.py` | `validate_arguments` — add cross-flag rules (e.g. intrusive requires base). Runs *after* config merge. |
| `mcp_fuzzer/cli/app.py` | Thin composition root: `SessionBootstrap` → `run_session` → `PostRunPresenter`. |
| `mcp_fuzzer/reports/crash_repro.py` | `write_findings_report` — optional top-level metadata block (paper citation + count), guarded by try/except. |
| `mcp_fuzzer/reports/formatters/plain_summary.py` | stdout summary — link the paper when a finding category is present. Import guarded by try/except ImportError. |

### Finding/probe conventions (from `auth_audit.py`)
- A `_finding(flaw_id, category, severity, detail, evidence)` helper stamps each
  finding with `flaw_id` + paper citation fields (`paper_arxiv_id`, `paper_url`,
  `paper_title`) into `evidence`.
- A module-level `frozenset` of categories (`AUTH_AUDIT_FLAW_CATEGORIES`) lets
  the report/summary code recognize the family.
- An `is_<x>_finding(finding)` predicate classifies findings for reporting.
- Read-only by default; intrusive probes behind an explicit opt-in flag, with
  "only against servers you are authorized to test" in help + docs.
- **Severity reflects false-positive risk** (PR #174 review lesson): optional-by-
  spec behavior → `info`; heuristics → `low`; enforceable defects → `high`.
- Probes that GET endpoints must pass `follow_redirects=False` per request when
  classification depends on seeing the raw 3xx (PR #174 critical fix).

### Transport hooks available
- `transport.probe_auth_discovery()` → dict with `status`, `www_authenticate`, etc.
- `JsonRpcAdapter(transport).get_tools()` → `list[dict]` of tool defs (name, description, inputSchema). This is the entry point for **tool-description/schema analysis** checks (no network beyond the normal session).
- `_build_transport_request(config)` + `build_driver_with_auth(...)` to build a transport (e.g. an unauth one: `{**config, "auth_manager": None}`).

### Test conventions
- Unit tests under `tests/unit/...`. Use `httpx.MockTransport(handler)` for HTTP probes (see `tests/unit/auth/test_auth_audit.py`).
- For tool-description/schema checks, just pass synthetic tool-def dicts — no network.
- Must pass in BOTH `tox -e tests -- tests/unit/` and `-p no:randomly`.
- `pytest.importorskip(...)` for optional server deps (starlette/mcp/uvicorn).

---

## Project conventions (from CLAUDE.md)

- **Branch first** off updated `main`; never commit to `main`. Name e.g. `mcp-tool-poisoning-checks`.
- Commit style: short imperative, no trailing period (`Add ...`, `Fix ...`).
- Before every commit: `tox -e ruff` + `tox -e tests -- <paths>`.
- Before PR/merge: ruff clean + full unit suite in BOTH orderings + codecov patch/project green (advisory) + e2e workflow for live-behavior changes.
- PRs against `main` on `https://github.com/Agent-Hellboy/mcp-server-fuzzer`.
- Co-author trailer on commits; 🤖 footer on PR bodies.
- Graphify graph in `graphify-out/` — query before grepping. Rebuild: `/graphify mcp_fuzzer tests --update`.

### Release 0.4.0 checklist (Phase 4)
1. All PRs merged to `main`; `git checkout main && git pull`.
2. `CHANGELOG.md`: promote `[Unreleased]` → dated `## [0.4.0] - YYYY-MM-DD`.
   (NOTE: PR #174 already left an `[Unreleased]` section with the OAuth audit entry — fold new checks in there.)
3. Bump `mcp_fuzzer/version.py` `VERSION = "0.4.0"` on `release-v0.4.0` branch; open "Bump version to 0.4.0" PR.
4. CI green (tests, lint, e2e, codecov) — run Testing Check.
5. Sanity: `.tox/tests/bin/python -m mcp_fuzzer --version` → `mcp-fuzzer v0.4.0`.
6. Merge bump PR, then tag + push `v0.4.0` (triggers publish.yml + docker-release.yml).
7. Verify PyPI serves 0.4.0 and the GitHub Release exists / is latest.

---

## § Research findings  (Phase 1 — 2026-06-17)

> ⚠️ **Verification caveat.** The deep-research run (`w57bc844n`) hit an account
> session limit during verify/synthesize. Only 2 claims got full 2/3 votes
> (tool poisoning, cross-server shadowing — both arXiv 2503.23278). The rest are
> **sourced but unverified** (verifier agents died = "abstain", NOT refuted).
> Treat arXiv IDs as candidates: **WebFetch-verify each before hard-coding a
> citation in code** (as done for 2605.22333). Re-run the research after the
> limit resets to fill verification gaps if desired.

### Papers / sources (19 surfaced)

| # | Source | What it gives us |
|---|--------|------------------|
| 1 | arXiv **2503.23278** (primary) | Tool poisoning ✅, cross-server shadowing ✅ (both VERIFIED), rug pulls, preference manipulation |
| 2 | arXiv **2512.08290** (SoK) | Resources/Prompts/Tools taxonomy; tool poisoning, rug pulls, shadowing; command/SQL/path injection via tool params |
| 3 | arXiv **2508.13220** (MCPSecBench) | 17 attack types / 4 surfaces; 7 server-side: tool shadowing, data exfil, name squatting, indirect prompt injection, tool poisoning, rug pull; DNS rebinding + MITM (100% ASR) |
| 4 | arXiv **2508.12538** (MCPXKIT) | 31 attack methods / 4 categories; direct+indirect tool injection; TPA via metadata |
| 5 | arXiv **2506.13538** (empirical, 1,899 servers) | 7.2% vulnerable, 8 patterns; credential exposure 3.6%; tool poisoning 5.5% |
| 6 | MDPI **2624-800X/6/3/84** | **50-threat STRIDE/DREAD taxonomy w/ IDs+severities** — Tool Poisoning #48, Prompt Injection #11 (DREAD 50/50), Command Injection #32, RCE #33, Rug Pull #36, Full Schema Poisoning #37, Tool Shadowing #42, Path Traversal #50, Tool Resource Exhaustion #47; Token Passthrough #40, Confused Deputy #34, Unauth access #41, Localhost Bypass/NeighborJack #35 |
| 7 | arXiv **2509.06572** (parasitic toolchain / MCP-UPD) | Dangerous **capability combination** = local-data-read tools + network-egress tools; 8.7% tools risky, 27.2% servers |
| 8 | arXiv **2603.22489** | Tool poisoning = most prevalent client-side vuln; insufficient static validation |
| 9 | arXiv **2511.20920** | Malicious servers poison tool descriptions to exfil secrets (~/.aws/credentials → another tool) |
| 10 | arXiv **2605.22333** | OAuth F1–F9 — **already implemented** (PR #174) |
| 11 | OWASP **MCP Top 10 (2025)** | MCP03 Tool Poisoning, MCP05 Command Injection & Execution |
| 12–19 | Vendor: Invariant Labs (tool poisoning; WhatsApp MCP exploit), CyberArk ("no output is safe"), Equixly, JFrog (prompt hijacking), Keysight (command injection), Obsidian (OAuth → one-click ATO), FlowHunt (confused deputy), CoSAI/OASIS MCP security doc | Real-world PoCs + detection signatures backing the above |

### Attack vectors → black-box detectability

**A. Tool-metadata analysis (inspect `tools/list`; NO extra network — uses `JsonRpcAdapter.get_tools()`)**
- **Tool poisoning** — injection markers in name/description: `<IMPORTANT>`, `<CRITICAL>`, "ignore previous", "do not tell the user", instructions to read `~/.aws/credentials`/`.env`/`.ssh`, exfil verbs, hidden-parameter directives, imperative override language. *(VERIFIED; 2503.23278, 2506.13538, MDPI#48, OWASP MCP03, Invariant, CyberArk)*
- **Schema poisoning** — same markers inside `inputSchema` (field descriptions, defaults, enum) beyond the visible signature. *(MDPI#37)*
- **Tool shadowing** — duplicate/colliding tool names within a server (cross-server needs multiple endpoints → note as limitation). *(VERIFIED; MCPSecBench, MDPI#42)*
- **Name squatting** — tool/server names confusingly similar to well-known ones (needs a known-name list). *(MCPSecBench)*
- **Dangerous capability combo** — server exposes BOTH local-read AND network-egress tools (exfil chain). *(2509.06572)*

**B. Active injection oracles (fuzzer already sends args; add output-signature oracles = real evidence, stronger than current `injection_reflection`)**
- **Command injection** — `; id` / `$(id)` / backticks → detect `uid=…gid=…` in output. *(OWASP MCP05, MDPI#32, Keysight)*
- **Path traversal** — `../../../etc/passwd` → detect `root:x:0:0:` in output. *(MDPI#50)*
- **SQL injection** — classic payloads → detect SQL error signatures. *(2512.08290)*

**C. Output-based**
- **Indirect prompt injection via tool output** — scan tool RESPONSE content for injected instructions/markers. *(MCPSecBench, CyberArk, 2508.12538)*

**D. Transport/session (HTTP)**
- **Insecure transport** — endpoint is `http://` not `https://`. *(MCPSecBench protocol-side)* — trivial.
- **Missing Origin validation / DNS rebinding** — server accepts a foreign `Origin` header (localhost MCP exposed to web). *(MCPSecBench)*

**E. Auth beyond F1–F9 (extend `auth_audit.py`) — HARDER black-box, likely advisory/defer**
- **Token passthrough** (MDPI#40), **confused deputy** (MDPI#34, Obsidian, FlowHunt), **unauthenticated access** (MDPI#41 — partly covered by existing `unauthenticated_tools`).

---

## § Proposed checks  (Phase 2 — prioritized for 0.4.0)

Effort: S=small, M=medium, L=large. Confidence = false-positive risk → severity.

| Rank | Check ID (`category`) | Family | Source(s) | Detection (black-box) | Effort | Sev |
|------|----------------------|--------|-----------|----------------------|--------|-----|
| 1 | `tool_poisoning` | metadata | 2503.23278✅, OWASP MCP03 | scan tool name/desc for injection markers | S | high |
| 2 | `schema_poisoning` | metadata | MDPI#37 | scan inputSchema text for markers | S | high |
| 3 | `tool_shadowing` | metadata | 2503.23278✅, MDPI#42 | duplicate tool names in a server | S | medium |
| 4 | `dangerous_capability_combo` | metadata | 2509.06572 | local-read + net-egress tags present | M | medium |
| 5 | `command_injection` | active oracle | OWASP MCP05, MDPI#32 | `$(id)` payload → `uid=` in output | M | critical |
| 6 | `path_traversal` | active oracle | MDPI#50 | `../etc/passwd` → `root:x:0:0:` | M | high |
| 7 | `sql_injection` | active oracle | 2512.08290 | payload → SQL error signature | M | high |
| 8 | `output_prompt_injection` | output | MCPSecBench, CyberArk | injected instructions in tool output | M | medium |
| 9 | `insecure_transport` | transport | MCPSecBench | endpoint scheme is `http://` | S | medium |
| 10 | `tool_name_squatting` | metadata | MCPSecBench | name ~ known-tool typosquat (needs list) | M | low |
| 11 | `missing_origin_validation` | transport | MCPSecBench | foreign `Origin` accepted (rebinding) | M | high |
| 12 | `token_passthrough` / `confused_deputy` | auth | MDPI#40/#34 | hard black-box → **advisory/defer** | L | — |

Notes:
- #1–3, #9 are quick wins with low FP risk → strong first PR.
- #5–7 (active oracles) strengthen the existing `injection_reflection` detector with real exploitation evidence; coordinate so they don't double-report.
- #11 needs care (an active cross-origin probe) → put behind the intrusive flag.
- #12 is hard to confirm externally → ship as advisory or defer past 0.4.0.

---

## § Raw sources (for the implementing agent to fetch + verify)

All 23 sources from research run `w57bc844n`. `claimCount` = how many claims were
extracted; quality is the workflow's own rating. **Verify each arXiv ID resolves
to the stated paper before citing it in code** (some are 2026-dated and unverified).

Primary (arXiv / standards):
- https://arxiv.org/abs/2503.23278  (5) — tool poisoning ✅, shadowing ✅, rug pull
- https://arxiv.org/abs/2512.08290  (5) — SoK; injection via params
- https://arxiv.org/abs/2508.13220  (5) — MCPSecBench  (also /html/2508.13220)
- https://arxiv.org/abs/2508.12538  (5) — MCPXKIT
- https://arxiv.org/abs/2506.13538  (5) — empirical 1,899 servers
- https://www.mdpi.com/2624-800X/6/3/84  (5) — 50-threat STRIDE/DREAD taxonomy
- https://arxiv.org/html/2509.06572v3  (4) — parasitic toolchain / MCP-UPD
- https://arxiv.org/abs/2603.22489  (5) — tool poisoning prevalence
- https://arxiv.org/html/2511.20920v1  (5) — desc poisoning → secret exfil
- https://arxiv.org/abs/2605.22333  (4) — OAuth F1–F9 (already implemented)
- https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025-Tool-Poisoning  (5)
- https://owasp.org/www-project-mcp-top-10/2025/MCP05-2025-Command-Injection&Execution  (5)
- https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md  (5)

Vendor / blog (PoCs + detection signatures):
- https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks  (5)
- https://invariantlabs.ai/blog/whatsapp-mcp-exploited  (5)
- https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe  (5)
- https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/  (5)
- https://jfrog.com/blog/mcp-prompt-hijacking-vulnerability/  (5)
- https://www.keysight.com/blogs/en/tech/nwvs/2026/01/12/mcp-command-injection-new-attack-vector  (5)
- https://www.obsidiansecurity.com/blog/when-mcp-meets-oauth-common-pitfalls-leading-to-one-click-account-takeover  (5)
- https://www.flowhunt.io/blog/mcp-authentication-authorization-oauth-confused-deputy/  (5)
- https://securityboulevard.com/2026/04/7-mcp-authentication-vulnerabilities-b2b-saas-vendors-must-prevent/  (0, flagged unreliable)

Raw workflow output (all 108→25 claims, votes, logs):
`tasks/w57bc844n.output` in the session task dir
(`/private/tmp/claude-501/-Users-proshan-mcp-server-fuzzer/27e2d672-c55e-4fc0-ba00-598db010a0a9/tasks/w57bc844n.output`).

---

## Decisions for the implementing agent to make (not yet decided)
- One umbrella `--security-audit` flag vs per-family flags (compose with existing `--auth-audit`)?
- One PR or grouped-by-theme PRs (metadata / injection / transport)?
- Include client-side / malicious-server-indicator checks, or server-side only for 0.4.0?
- Active oracles (#5–7) vs the existing `injection_reflection` detector — avoid double-reporting.
- Re-run research after the session limit resets to verify the abstained claims.
