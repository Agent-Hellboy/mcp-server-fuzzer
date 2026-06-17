"""Guard against layer violations in package import edges."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2] / "mcp_fuzzer"

# (package_dir, forbidden top-level package segments under mcp_fuzzer)
FORBIDDEN_IMPORTS: list[tuple[str, tuple[str, ...]]] = [
    ("diagnostics", ("reports",)),
    ("reports", ("diagnostics",)),
    ("transport", ("orchestrator", "cli")),
    ("auth", ("orchestrator", "cli")),
    ("client", ("orchestrator",)),
    ("safety_system", ("orchestrator", "cli")),
    ("fuzz_engine", ("orchestrator", "cli")),
    ("config", ("orchestrator", "cli", "client", "reports", "diagnostics")),
]


def _module_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module.split(".")[0])
    return modules


@pytest.mark.parametrize("package_dir,forbidden", FORBIDDEN_IMPORTS)
def test_package_respects_import_layers(package_dir: str, forbidden: tuple[str, ...]):
    base = ROOT / package_dir
    if not base.is_dir():
        pytest.skip(f"missing package {package_dir}")
    violations: list[str] = []
    for path in base.rglob("*.py"):
        imported = _module_imports(path)
        for segment in forbidden:
            if segment in imported:
                violations.append(f"{path.relative_to(ROOT)} imports {segment}")
    assert not violations, "\n".join(violations)
