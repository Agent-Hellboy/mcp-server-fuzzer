# mcp-fuzzer — Architecture

A black-box fuzzer/auditor for MCP servers. It connects to a running server over
stdio/HTTP/SSE, drives fuzz inputs at it, and diagnoses the responses for
security and robustness issues.

This document is the **target design**. It encodes the rules we restructured the
codebase around so that extending it stays easy.

---

## 1. The one rule: dependencies point down

Packages are layered. **Imports only ever point downward.** A lower layer must
never import an upper layer (that creates cycles and turns the conductor into a
grab-bag).

```
            ┌─────────────────────────────────────────┐
  L4  app   │ cli/                                      │  argv → settings → run
            └───────────────────┬───────────────────────┘
                                │
  L3  conductor   ┌─────────────▼─────────────┐
                  │ orchestrator/             │  drives a session end-to-end
                  └───┬───────────┬───────────┘
                      │           │
  L2  capabilities ┌──▼──┐   ┌────▼──────┐   ┌─────────┐
                   │fuzz_│   │diagnostics│   │ reports │  do the work / analysis
                   │engine│  └────┬──────┘   └────┬────┘
                   └──┬──┘        │               │
                      └─────┬─────┴───────┬───────┘
  L1  subsystems   ┌────────▼───┐ ┌───────▼────┐ ┌──────┐ ┌──────────────┐
                   │ transport/ │ │ auth/      │ │client│ │ safety_system│
                   └──────┬─────┘ └─────┬──────┘ └───┬──┘ └──────┬───────┘
                          │             │            │           │
  L0  foundation   ┌──────▼─────────────▼────────────▼───────────▼───────┐
                   │ config/   exceptions   logging/   utils/   corpus    │
                   └───────────────────────────────────────────────────────┘
```

- **L4 `cli/`** — parse args, merge config, validate, build settings, call the app.
- **L3 `orchestrator/`** — the conductor. Owns one session: *run the fuzz plan
  (drives `fuzz_engine`) → run the diagnostics pipeline → persist*. Thin; holds
  no domain logic of its own.
- **L2 capabilities** — `fuzz_engine/` (how to fuzz), `diagnostics/` (turn results
  + live probes into `Finding`s), `reports/` (format/export). Peers; they don't
  import each other.
- **L1 subsystems** — `transport/`, `auth/`, `client/`, `safety_system/`. Shared
  services used by L2/L3. Peers.
- **L0 foundation** — `config/`, `exceptions`, `logging/`, `utils/`, `corpus`.
  Imported by everyone; import almost nothing.

### Session flow (the spine)
```
cli.run_cli
  └─ build settings ──► cli/app.run_fuzz_app
                          ├─ SessionBootstrap (transport, client, reporter, context)
                          └─ orchestrator.run_session(context) → SessionResult
                                ├─ orchestrator/run_plan + plan.execute   → fuzz_engine
                                ├─ audit_registry → diagnostics phases
                                └─ persist_session_findings
  └─ PostRunPresenter (stdout summaries, exports via FuzzReportPresenter)
```

---

## 2. Packages & responsibilities

| Package | Layer | Responsibility |
|---------|-------|----------------|
| `cli/` | L4 | argument parsing, config merge, validation, bootstrap, post-run, entrypoint |
| `orchestrator/` | L3 | session models, run plan, audit registry, `run_session`, persist |
| `fuzz_engine/` | L2 | executors, mutators, strategies, runtime/watchdog |
| `diagnostics/` | L2 | `Finding` model, fuzz-run classifier, paper-backed audits (auth + server) |
| `reports/` | L2 | report collection, formatters, output protocol, exports |
| `transport/` | L1 | stdio/HTTP/SSE drivers, JSON-RPC adapter, catalog, bootstrap, retry wrapper |
| `auth/` | L1 | OAuth client (discovery, registration, grants, token cache) |
| `client/` | L1 | MCP client facades (`fuzzer_client`, `tool_client`, `protocol_client`) |
| `safety_system/` | L1 | input blocking, danger detection, fs sandbox, safety events |
| `config/` | L0 | constants, config singleton, loaders, schema |
| `spec_guard/`, `utils/`, `logging/`, `corpus` | L0 | foundation helpers |

---

## 3. Structural conventions (how we keep it clean)

These are the rules the restructure enforced. Follow them when adding code.

1. **Flat over deep.** Prefer flat modules in a package over nested subpackages.
   Cap real nesting at ~2 levels. (We removed the only 4-deep paths.)
2. **No single-file packages.** A directory that contains only `__init__.py` +
   one real module should just be that module. (`x/y/thing.py` → `x/thing.py`.)
3. **No logic in `__init__.py`.** `__init__.py` re-exports the package's public
   surface — nothing more. (We moved a 527-line reporter class out of an
   `__init__.py`.) Keep `__all__` lists in sync.
4. **A subpackage must earn its keep** — ≥3 cohesive modules, or a genuine
   independent concern. Otherwise it's flat modules with a shared name prefix
   (e.g. `aggressive_tool_strategy.py`, not `aggressive/tool_strategy.py`).
5. **Don't add an interface for one implementation.** A Port/ABC with a single
   adapter is ceremony, not abstraction (see §4). Add the seam when the second
   implementation actually arrives.
6. **The conductor stays thin.** `orchestrator/` sequences and owns no domain
   logic. New checks/strategies go in `diagnostics`/`fuzz_engine`, not here.
7. **Audits are best-effort and labelled.** A diagnostics phase returns
   `(findings, ran)` so a *skipped* audit is never logged as a clean pass.
   Severity reflects false-positive risk (info/low for heuristics, high for
   enforceable defects).

### Adding a new diagnostic check (the common case)
1. Add a function in `diagnostics/server.py` (or a new flat `diagnostics/*.py`).
2. Re-export it from `diagnostics/__init__.py`.
3. Call it from a phase in `orchestrator/session.py`; gate it on a CLI flag.
4. Wire the flag in `cli/parser.py`, `cli/config_merge.py` (mapping **and**
   merged dict), `cli/validators.py` (cross-flag rules).
5. Unit-test with synthetic tool dicts / `httpx.MockTransport`; pass in both
   `tox` orderings.

---

## 4. SOLID & naming

The structural rules above are SOLID applied to *packages*; the same principles
drive module/symbol design:

- **SRP** — a module/class does one thing. Smell: a class with both `fuzz_*` and
  `print_*`/`generate_report` methods is two responsibilities wearing one name.
- **OCP / ISP** — extend via small focused seams (a new `diagnostics/*.py`, a new
  `Mutator`, a new `RunCommand`), not by editing a god-class. Keep interfaces
  narrow (`ReportSaver` ⊂ `ReportFormatter`).
- **DIP** — depend on the abstraction *only where polymorphism is real*
  (`TransportDriver` → 4 drivers, `AuthProvider` → many). A one-impl ABC is not
  DIP, it's ceremony — we deleted `ConfigPort` and `SafetyPort`.
- **SRP** — `MCPFuzzerClient` fuzzes; `FuzzReportPresenter` / `PostRunPresenter`
  print/export; `cli/app.py::run_fuzz_app` is the composition root; `SessionBootstrap`
  wires dependencies.
- **Names state the role, not the layer mechanics.** `base.py` (a concrete
  facade) → `fuzzer_client.py`; the real base class is `mutators/base.py::Mutator`.
  Avoid near-twin module names (`spec_version` vs `spec_versions` — merged).
- **Naming conventions:** packages = plural domain area (`reports/`, `mutators/`);
  modules = the noun they own (`reporter.py`, `retrying.py`); flat variants carry
  a prefix (`aggressive_tool_strategy.py`). One concept → one home (we merged
  `protocol_types.py` into `protocol_registry.py`).

## 5. Recommended follow-ups (behavior-sensitive — get sign-off)

All items from the 2026-06 SOLID/architecture pass are **done** except optional
future work:

- ~~**Split `MCPFuzzerClient` (SRP).**~~ Done: `client/report_presenter.py`.
- ~~**Split `protocol_client.py`.**~~ Done: `protocol_specs.py`, `protocol_send_handlers.py`,
  `protocol_listings.py`, facade `protocol_client.py`.
- ~~**Relocate the composition root.**~~ Done: `cli/app.py`, `cli/bootstrap.py`,
  `cli/post_run.py`.
- ~~**Move run plan to orchestrator.**~~ Done: `orchestrator/run_plan.py`,
  `orchestrator/models.py::SessionContext`.
- ~~**Transport bootstrap.**~~ Done: `transport/bootstrap.py` (auth-aware driver build).
- ~~**CLI runtime.**~~ Done: `cli/runtime/` (async runner, retry, argv builder).
- ~~**Dedup `fuzzerreporter/`.**~~ Done: merged into `fuzz_engine/executor/results.py`.
- ~~**Split god-modules.**~~ Done: `diagnostics/server_*`, `auth_oauth_probes`,
  `spec_checks_*`, `tool_client_*`, `cli/parser_*`.
- ~~**Audit phase registry.**~~ Done: `orchestrator/audit_registry.py`.
- ~~**Typed session config.**~~ Done: `cli/session_settings.py::SessionSettings`.
- ~~**Split `reports/reporter.py`.**~~ Done: `reporter_console.py`,
  `reporter_snapshot.py`, `reporter_export.py`; facade `reporter.py`.

---

## 6. Restructure log (done)

`config/`, `reports/`, `fuzz_engine` strategies flattened; security-audit feature in
flat `diagnostics/` + top-level `orchestrator/`; client god-modules split; composition
root and bootstrap in `cli/`; transport bootstrap relocated; executor result types
unified. Full unit suite green in both orderings after each step.
