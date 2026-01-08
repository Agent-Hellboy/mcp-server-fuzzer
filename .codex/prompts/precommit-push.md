---
description: Run pre-commit and push the current branch.
argument-hint: [REMOTE=origin] [BRANCH=<branch>]
---

Run `pre-commit run --all-files`. If any hook modifies files, run the command
again to ensure a clean pass. If it still fails, stop and report the error.

Determine the branch to push: use $BRANCH if provided; otherwise use the current
branch from `git rev-parse --abbrev-ref HEAD`.
Determine the remote: use $REMOTE if provided; otherwise default to `origin`.

Push the branch with `git push $REMOTE <branch>`.
