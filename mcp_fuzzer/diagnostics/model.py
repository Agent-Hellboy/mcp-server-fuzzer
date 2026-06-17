"""Shared issue record used by fuzz classifiers and security audits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Severity ranking used for sorting/reporting.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """A single categorized issue discovered during fuzzing or security audits."""

    category: str
    severity: str
    kind: str  # "tool", "protocol", or "auth"
    target: str
    run: int | None
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "kind": self.kind,
            "target": self.target,
            "run": self.run,
            "detail": self.detail,
            "evidence": self.evidence,
        }
