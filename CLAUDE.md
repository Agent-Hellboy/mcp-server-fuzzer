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

## Pull Requests

Open PRs against `main` on `https://github.com/Agent-Hellboy/mcp-server-fuzzer`.
