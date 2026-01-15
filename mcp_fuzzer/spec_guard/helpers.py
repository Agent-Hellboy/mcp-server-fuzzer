"""Shared helpers for spec guard checks and runners."""

from __future__ import annotations

from typing import Any, TypedDict


class SpecCheck(TypedDict, total=False):
    """Minimal spec check record for reporting."""

    id: str
    status: str
    message: str
    spec_id: str
    spec_url: str
    details: dict[str, Any]


def fail(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a failure SpecCheck."""
    return {
        "id": check_id,
        "status": "FAIL",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def warn(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a warning SpecCheck."""
    return {
        "id": check_id,
        "status": "WARN",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }


def pass_check(check_id: str, message: str, spec: dict[str, str]) -> SpecCheck:
    """Create a passing SpecCheck."""
    return {
        "id": check_id,
        "status": "PASS",
        "message": message,
        "spec_id": spec.get("spec_id", ""),
        "spec_url": spec.get("spec_url", ""),
    }
