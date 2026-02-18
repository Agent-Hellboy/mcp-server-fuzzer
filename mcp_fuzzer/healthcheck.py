#!/usr/bin/env python3
"""Lightweight container healthcheck for MCP Fuzzer.

Designed to be safe under distroless (no shell, minimal utilities).
Performs quick, side-effect free checks:
1. Verify package import + version is readable.
2. Confirm schemas directory mounted (needed for fuzzing).
3. Optionally emit JSON diagnostics when invoked with --verbose or --json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _check_version() -> str:
    try:
        from .version import VERSION as __version__
    except Exception as exc:  # pragma: no cover - healthcheck only
        raise RuntimeError(f"import failure: {exc}") from exc
    return __version__


def _check_schemas() -> bool:
    # Distroless copies schemas to /app/schemas; keep relative fallback for tests
    candidates = [
        Path("/app/schemas"),
        Path(__file__).resolve().parent.parent / "schemas",
    ]
    for path in candidates:
        if path.exists() and any(path.iterdir()):
            return True
    return False


def run_healthcheck(verbose: bool = False) -> int:
    status: dict[str, object] = {"status": "ok"}
    try:
        status["version"] = _check_version()
        status["schemas_present"] = _check_schemas()
        if not status["schemas_present"]:
            raise RuntimeError("schemas directory missing or empty")
    except Exception as exc:  # pragma: no cover - exercised in tests
        status["status"] = "error"
        status["error"] = str(exc)

    if verbose:
        print(json.dumps(status, sort_keys=True))

    return 0 if status["status"] == "ok" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MCP Fuzzer container healthcheck (distroless-safe)."
    )
    parser.add_argument(
        "--verbose", "--json", action="store_true", help="Emit JSON status to stdout"
    )
    args = parser.parse_args(argv)
    return run_healthcheck(verbose=args.verbose)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
