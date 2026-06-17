"""Top-level session orchestration.

The orchestrator sits above ``fuzz_engine`` and ``findings``: it drives the
fuzz run and then the paper-backed analysis/audit pipeline, classifying runs
into findings and persisting them.
"""

from .audit_phases import (
    log_oauth_audit_results,
    log_server_audit_results,
    run_auth_bypass_phase,
    run_oauth_audit_phase,
    run_server_audit_phase,
)
from .audit_registry import AuditContext, AuditPhase, AuditPhaseResult, run_audit_phases
from .models import SessionContext, SessionResult
from .persist import persist_session_findings
from .run_plan import RunPlan, build_run_plan
from .session import collect_session_findings, run_session

__all__ = [
    "AuditContext",
    "AuditPhase",
    "AuditPhaseResult",
    "SessionContext",
    "SessionResult",
    "RunPlan",
    "build_run_plan",
    "run_session",
    "collect_session_findings",
    "persist_session_findings",
    "run_audit_phases",
    "log_oauth_audit_results",
    "log_server_audit_results",
    "run_auth_bypass_phase",
    "run_oauth_audit_phase",
    "run_server_audit_phase",
]
