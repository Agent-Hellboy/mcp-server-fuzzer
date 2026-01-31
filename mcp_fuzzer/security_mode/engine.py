#!/usr/bin/env python3
"""Security mode engine for pre-call expectations and post-call verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence
from urllib.parse import urlparse

from .policy import SecurityPolicy


@dataclass(frozen=True)
class SecurityExpectation:
    """Human-readable expectations derived from args."""

    path_violation_expected: bool = False
    network_violation_expected: bool = False
    command_violation_expected: bool = False
    suspicious_paths: tuple[str, ...] = field(default_factory=tuple)
    suspicious_hosts: tuple[str, ...] = field(default_factory=tuple)
    suspicious_commands: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityVerdict:
    """Outcome information produced after a tool call."""

    policy_violations: list[dict[str, Any]]
    semantic_mismatch: dict[str, Any] | None


_CONTROL_MAPPING: dict[str, list[str]] = {
    "filesystem": ["MCP-FS-02"],
    "process": ["MCP-EXEC-01"],
    "network": ["MCP-NET-01"],
    "authz": ["MCP-AUTHZ-01"],
    "input": ["MCP-INPUT-01"],
}

_SHELL_TOKENS = (";", "&&", "||", "|", "`", "$(", "${", "\n", "%0a", "%0d")


def _flatten_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for entry in value.values():
            strings.extend(_flatten_strings(entry))
    elif isinstance(value, (list, tuple, set)):
        for entry in value:
            strings.extend(_flatten_strings(entry))
    return strings


def _extract_host(value: str) -> str | None:
    raw = value.strip()
    if raw.startswith("[") and "]" in raw:
        bracket_end = raw.index("]")
        return raw[1:bracket_end].lower()
    parsed = urlparse(raw)
    if parsed.hostname:
        return parsed.hostname.lower()
    if ":" in raw and "." in raw:
        candidate = raw.split(":", 1)[0]
        if candidate:
            return candidate.lower()
    if "." in raw:
        return raw.lower()
    return None


def _looks_like_path(value: str) -> bool:
    return "/" in value or "\\" in value or value.startswith(".")


def _contains_shell_tokens(value: str) -> bool:
    low = value.lower()
    return any(token in low for token in _SHELL_TOKENS)


def _map_domain(identifier: str | None) -> str:
    if identifier in _CONTROL_MAPPING:
        return identifier
    if identifier == "process":
        return "process"
    if identifier == "network":
        return "network"
    return "filesystem"


class SecurityModeEngine:
    """Compute expectations and verdicts for security mode runs."""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def pre_call_expectations(
        self, tool_name: str, args: dict[str, Any] | None
    ) -> SecurityExpectation:
        suspicious_paths: list[str] = []
        suspicious_hosts: list[str] = []
        suspicious_commands: list[str] = []
        path_violation = False
        net_violation = False
        cmd_violation = False

        payload = args or {}
        for value in _flatten_strings(payload):
            if not value:
                continue

            if _looks_like_path(value):
                if not self.policy.is_path_allowed(value):
                    path_violation = True
                    suspicious_paths.append(value)

            host = _extract_host(value)
            if host and not self.policy.is_host_allowed(host):
                net_violation = True
                suspicious_hosts.append(host)

            if _contains_shell_tokens(value):
                cmd_violation = True
                suspicious_commands.append(value)

        # If policy restricts commands to a very short allowlist, assume any tool
        # calling `command`/`cmd` arguments should be scrutinized.
        if self.policy.proc_allow:
            for key, value in args.items():
                if isinstance(value, str) and key.lower().endswith("command"):
                    normalized = self.policy.normalize_command(value)
                    if normalized and normalized not in self.policy.proc_allow:
                        cmd_violation = True
                        suspicious_commands.append(value)
        else:
            for key, value in args.items():
                if (
                    isinstance(value, str)
                    and key.lower().endswith("command")
                    and " " in value.strip()
                ):
                    cmd_violation = True
                    suspicious_commands.append(value)

        return SecurityExpectation(
            path_violation_expected=path_violation,
            network_violation_expected=net_violation,
            command_violation_expected=cmd_violation,
            suspicious_paths=tuple(suspicious_paths),
            suspicious_hosts=tuple(suspicious_hosts),
            suspicious_commands=tuple(suspicious_commands),
        )

    def post_call_verdicts(
        self,
        success: bool,
        exception: Exception | None,
        oracle_findings: Sequence[dict[str, Any]],
        expectations: SecurityExpectation | None,
    ) -> SecurityVerdict:
        policy_violations: list[dict[str, Any]] = []

        for finding in oracle_findings:
            domain = _map_domain(finding.get("oracle"))
            violation = {
                "domain": domain,
                "type": finding.get("type"),
                "details": finding,
                "controls": _CONTROL_MAPPING.get(domain, []),
            }
            policy_violations.append(violation)

        semantic_mismatch = None
        if policy_violations:
            status = "forbidden_side_effect" if success else "side_effect_on_error"
            semantic_mismatch = {
                "status": status,
                "violations": policy_violations,
                "expectations": {
                    "path_violation_expected": expectations.path_violation_expected
                    if expectations
                    else False,
            "network_violation_expected": (
                expectations.network_violation_expected if expectations else False
            ),
            "command_violation_expected": (
                expectations.command_violation_expected if expectations else False
            ),
            "suspicious_paths": list(
                expectations.suspicious_paths
                if expectations
                        else []
                    ),
                    "suspicious_hosts": list(
                        expectations.suspicious_hosts
                        if expectations
                        else []
                    ),
                    "suspicious_commands": list(
                        expectations.suspicious_commands
                        if expectations
                        else []
                    ),
                },
            }

        return SecurityVerdict(
            policy_violations=policy_violations,
            semantic_mismatch=semantic_mismatch,
        )
