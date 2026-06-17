"""Registry of audit phases that drive session findings collection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .audit_phases import (
    log_oauth_audit_results,
    log_server_audit_results,
    run_auth_bypass_phase,
    run_oauth_audit_phase,
    run_server_audit_phase,
)


@dataclass(frozen=True)
class AuditContext:
    """Inputs shared by all audit phases."""

    config: dict[str, Any]
    transport: Any
    mode: str
    tool_results: dict[str, Any] | None
    protocol_results: dict[str, Any] | None
    build_transport_request: Callable[..., Any]


@dataclass(frozen=True)
class AuditPhaseResult:
    """Output from a single audit phase."""

    findings: list[Any]
    ran: bool


class AuditPhase(Protocol):
    """Single audit phase invoked by the registry."""

    name: str

    def applies(self, ctx: AuditContext) -> bool: ...

    async def run(self, ctx: AuditContext) -> AuditPhaseResult: ...

    def log_results(self, result: AuditPhaseResult, config: dict[str, Any]) -> None: ...


class AuthBypassAuditPhase:
    name = "auth_bypass"

    def applies(self, ctx: AuditContext) -> bool:
        return ctx.mode in ("tools", "all")

    async def run(self, ctx: AuditContext) -> AuditPhaseResult:
        findings = await run_auth_bypass_phase(
            ctx.config, ctx.build_transport_request
        )
        return AuditPhaseResult(findings=findings, ran=True)

    def log_results(self, result: AuditPhaseResult, config: dict[str, Any]) -> None:
        return None


class OAuthAuditPhase:
    name = "oauth"

    def applies(self, _ctx: AuditContext) -> bool:
        return True

    async def run(self, ctx: AuditContext) -> AuditPhaseResult:
        findings, ran = await run_oauth_audit_phase(
            ctx.config, ctx.transport, ctx.build_transport_request
        )
        return AuditPhaseResult(findings=findings, ran=ran)

    def log_results(self, result: AuditPhaseResult, config: dict[str, Any]) -> None:
        log_oauth_audit_results(
            result.findings,
            enabled=bool(config.get("auth_audit")),
            ran=result.ran,
        )


class ServerAuditPhase:
    name = "server"

    def applies(self, _ctx: AuditContext) -> bool:
        return True

    async def run(self, ctx: AuditContext) -> AuditPhaseResult:
        findings, ran = await run_server_audit_phase(
            ctx.config, ctx.transport, ctx.tool_results
        )
        return AuditPhaseResult(findings=findings, ran=ran)

    def log_results(self, result: AuditPhaseResult, config: dict[str, Any]) -> None:
        log_server_audit_results(
            result.findings,
            enabled=bool(config.get("security_audit")),
            ran=result.ran,
        )


def default_audit_phases() -> list[AuditPhase]:
    return [AuthBypassAuditPhase(), OAuthAuditPhase(), ServerAuditPhase()]


async def run_audit_phases(
    ctx: AuditContext,
    phases: list[AuditPhase] | None = None,
) -> list[Any]:
    """Run all applicable audit phases and return combined findings."""
    registry = phases if phases is not None else default_audit_phases()
    findings: list[Any] = []
    for phase in registry:
        if not phase.applies(ctx):
            continue
        result = await phase.run(ctx)
        findings.extend(result.findings)
        phase.log_results(result, ctx.config)
    return findings


__all__ = [
    "AuditContext",
    "AuditPhase",
    "AuditPhaseResult",
    "default_audit_phases",
    "run_audit_phases",
]
