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
  └─ build settings ──► orchestrator.run_session(context)
                          ├─ build_run_plan + plan.execute      → fuzz_engine
                          ├─ collect_session_findings           → diagnostics
                          │     ├─ classify_fuzz_runs (crash/hang/leak/…)
                          │     ├─ auth audit (F1–F9)            [--auth-audit]
                          │     └─ server audit (poisoning/…)    [--security-audit]
                          └─ persist_session_findings → findings.json + crash repros
  └─ reporter renders summaries / standardized reports / exports
```

---

## 2. Packages & responsibilities

| Package | Layer | Responsibility |
|---------|-------|----------------|
| `cli/` | L4 | argument parsing, config merge, validation, entrypoint |
| `orchestrator/` | L3 | drive a session: fuzz run → diagnostics → persist (`run_session`) |
| `fuzz_engine/` | L2 | executors, mutators, strategies, runtime/watchdog |
| `diagnostics/` | L2 | `Finding` model, fuzz-run classifier, paper-backed audits (auth + server) |
| `reports/` | L2 | report collection, formatters, output protocol, exports |
| `transport/` | L1 | stdio/HTTP/SSE drivers, JSON-RPC adapter, catalog, retry wrapper |
| `auth/` | L1 | OAuth client (discovery, registration, grants, token cache) |
| `client/` | L1 | MCP client wrapper, run-plan runtime, transport factory |
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
- **Names state the role, not the layer mechanics.** `base.py` (a concrete
  facade) → `fuzzer_client.py`; the real base class is `mutators/base.py::Mutator`.
  Avoid near-twin module names (`spec_version` vs `spec_versions` — merged).
- **Naming conventions:** packages = plural domain area (`reports/`, `mutators/`);
  modules = the noun they own (`reporter.py`, `retrying.py`); flat variants carry
  a prefix (`aggressive_tool_strategy.py`). One concept → one home (we merged
  `protocol_types.py` into `protocol_registry.py`).

## 5. Recommended follow-ups (behavior-sensitive — get sign-off)

- **Split `MCPFuzzerClient` (SRP).** `client/fuzzer_client.py` mixes a *fuzzing
  facade* (`fuzz_tool`, `fuzz_all_protocol_types`, …) with a *reporting facade*
  (`print_*`, `generate_*_report`). Extract the reporting methods to a collaborator
  that wraps the `reporter`, leaving the client to orchestrate fuzzing only.
- **`client/protocol_client.py` is a 1049-line god-module.** Split by concern
  (resources / prompts / tools / spec) behind the existing facade. Large; ~30
  tests patch it — do as its own focused pass.
- **Relocate the composition root.** `client/main.py::unified_client_main` is
  application wiring (transport + client + reporter + orchestrator), i.e. L4 app
  glue living inside an L1 subsystem. Move it to the app layer (e.g. `cli/app.py`)
  so `client/` is purely "the MCP fuzzing client".
- **`fuzz_engine/fuzzerreporter/`** — 3-module package; fine as-is, but its
  result-building overlaps `reports/collector` — worth a dedup look.

---

## 5. Restructure log (done)

`config/`, `reports/`, `fuzz_engine` strategies flattened; the 527-line reporter
moved out of `__init__`; the security-audit feature flattened into `diagnostics/`
+ a top-level `orchestrator/` that now drives `fuzz_engine`; `client/` single-file
dirs, `transport/wrappers/`, `safety_system/reporting/` flattened; dead empty
`security_mode/` removed. Full unit suite green (2524) in both orderings after
each step.
