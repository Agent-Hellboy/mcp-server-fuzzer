# AI Agent Instructions

## Branch Creation

Always create a feature branch before making any code changes:

```bash
git checkout main
git pull origin main
git checkout -b <descriptive-branch-name>
```

Name the branch after the feature or fix, for example:
- `oauth-client-credentials-auth`
- `git-branch-isolation`
- `fix-batch-auth-bypass`

Never commit directly to `main`.

## Commit Message Style

Follow the project's short imperative style — no trailing period:

```
Add <feature>
Fix <bug>
Refactor <component>
Update <thing>
Remove <thing>
```

Examples from this repo:
- `Add OAuth client credentials auth`
- `Add git branch isolation for AI agents`
- `Fix batch JSON-RPC auth bypass in test server`
- `Refine reporting boundaries and result contracts`

## Lint and Tests

Run before every commit:

```bash
tox -e ruff                  # lint
tox -e tests -- <test paths> # unit tests
```

### tox venv setup

tox creates a managed venv at `.tox/tests/`. Use its Python for anything that
needs project dependencies (running the server, the CLI, ad-hoc scripts):

```bash
# First run: tox creates the venv automatically
tox -e tests -- tests/unit/

# Use the tox Python directly for scripts / servers / CLI
.tox/tests/bin/python examples/test_server.py
.tox/tests/bin/python -m mcp_fuzzer --help

# Install extra deps into the tox venv (e.g. server deps)
.tox/tests/bin/pip install uvicorn mcp anyio starlette
```

**Never use the system `python3` or `pip3` for project code** — the repo uses a
managed environment and the system Python may lack required packages or be
protected by PEP 668.

## Codebase Exploration — Use Graphify First

A knowledge graph of this repo lives in `graphify-out/`. **Before exploring the code manually, query the graph:**

```bash
# Ask anything about structure, coverage, relationships
graphify query "how does X work"
graphify query "what calls Y"
graphify path "AuthModule" "Database"
graphify explain "OAuthClientCredentialsAuth"
```

Graphify is faster than grepping and surfaces cross-file relationships the raw code doesn't make obvious. Only fall back to `grep`/`Read` when the graph answer is insufficient.

To rebuild the graph after large changes:

```bash
/graphify mcp_fuzzer tests --update
```

## Pull Requests

Open PRs against `main` on `https://github.com/Agent-Hellboy/mcp-server-fuzzer`.

## Testing Check

Run this before opening a PR and before merging:

```bash
tox -e ruff                                   # lint must be clean
tox -e tests -- tests/unit/                   # full unit suite (random order)
tox -e tests -- tests/unit/ -p no:randomly    # again in deterministic order
```

- Both orderings must pass. Running both catches test-isolation bugs
  (global state / `sys.modules` leakage) that only surface under a particular
  order — `pytest-randomly` shuffles order in CI.
- Tests that need optional server deps (`starlette`/`mcp`/`uvicorn`) must
  `pytest.importorskip(...)` so they skip cleanly where those deps are absent
  (the `tests` env does not install them); otherwise CI fails at collection.
- Coverage: CI runs Codecov with `patch` and `project` gates. Add tests for new
  code so `codecov/patch` clears its target; the gates are advisory (a PR can
  still merge) but should be green for feature work.
- For changes touching live behavior, also confirm the `e2e-test` workflow
  passes — it fuzzes the upstream "everything" MCP server end to end.

## Release Readiness Check

Before cutting a release `vX.Y.Z`:

1. All intended PRs are merged to `main`; `git checkout main && git pull`.
2. `CHANGELOG.md` has a dated `## [X.Y.Z]` section listing the changes.
3. Bump `mcp_fuzzer/version.py` (`VERSION = "X.Y.Z"`) on a `release-vX.Y.Z`
   branch and open a "Bump version to X.Y.Z" PR.
4. CI on that PR is green (tests, lint, e2e, codecov) — run the Testing Check.
5. Sanity-check the build: `.tox/tests/bin/python -m mcp_fuzzer --version`
   prints `mcp-fuzzer vX.Y.Z`.
6. Merge the bump PR, then tag and push:

   ```bash
   git checkout main && git pull origin main
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The `v*` tag triggers `publish.yml` (build + upload to PyPI) and
   `docker-release.yml` (build + push the image).
7. Verify after publish: PyPI serves `mcp-fuzzer X.Y.Z`
   (`https://pypi.org/pypi/mcp-fuzzer/json`) and the GitHub Release `vX.Y.Z`
   exists and is marked latest.
