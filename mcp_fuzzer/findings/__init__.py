"""MCP findings: issue model, fuzz-run classifiers, and paper-backed audits.

Flat modules (no nested packages):
- ``model``       -- the ``Finding`` record and severity ordering
- ``classify``    -- turn fuzz runs into categorized findings
- ``auth_oauth``  -- OAuth F1-F9 audit (arXiv 2605.22333)
- ``auth_probe``  -- in-fuzz auth-bypass / open-tool probes
- ``server``      -- tool-metadata, output-oracle, and transport checks

The post-fuzz pipeline that *drives* these checks lives in
``mcp_fuzzer.orchestrator``; this package is the pure check library.
"""

from .model import SEVERITY_ORDER, Finding
from .classify import classify_fuzz_runs, summarize_findings
from .auth_oauth import (
    AUTH_AUDIT_FLAW_CATEGORIES,
    AUTH_AUDIT_PAPER_ARXIV_ID,
    AUTH_AUDIT_PAPER_URL,
    audit_as_metadata,
    auth_audit_paper_evidence,
    auth_audit_report_metadata,
    discover_and_audit_authorization_server,
    inspect_state_for_routing,
    is_auth_audit_finding,
    probe_blind_client_trust,
    probe_code_replay,
    probe_consent_page_bypass,
    probe_malicious_dcr,
    probe_open_redirect,
    probe_pkce_downgrade_active,
    probe_pkce_layer_inconsistency,
    probe_weak_state,
    run_auth_endpoint_audit,
    run_post_authorization_audit,
)
from .auth_probe import (
    is_auth_enforced,
    probe_advertised_auth_open_tools,
    probe_auth_bypass,
    secured_tool_names,
)
from .server import (
    SERVER_AUDIT_FLAW_CATEGORIES,
    TOOL_POISONING_PAPER_ARXIV_ID,
    audit_insecure_transport,
    audit_tool_metadata,
    audit_tool_run_oracles,
    is_server_audit_finding,
    run_server_audit,
    server_audit_paper_evidence,
    server_audit_report_metadata,
)
__all__ = [
    # model + classification
    "Finding",
    "SEVERITY_ORDER",
    "classify_fuzz_runs",
    "summarize_findings",
    # auth audit (OAuth F1-F9)
    "AUTH_AUDIT_FLAW_CATEGORIES",
    "AUTH_AUDIT_PAPER_ARXIV_ID",
    "AUTH_AUDIT_PAPER_URL",
    "audit_as_metadata",
    "auth_audit_paper_evidence",
    "auth_audit_report_metadata",
    "discover_and_audit_authorization_server",
    "inspect_state_for_routing",
    "is_auth_audit_finding",
    "probe_blind_client_trust",
    "probe_code_replay",
    "probe_consent_page_bypass",
    "probe_malicious_dcr",
    "probe_open_redirect",
    "probe_pkce_downgrade_active",
    "probe_pkce_layer_inconsistency",
    "probe_weak_state",
    "run_auth_endpoint_audit",
    "run_post_authorization_audit",
    # in-fuzz auth probes
    "is_auth_enforced",
    "probe_advertised_auth_open_tools",
    "probe_auth_bypass",
    "secured_tool_names",
    # server audit (tool metadata / oracles / transport)
    "SERVER_AUDIT_FLAW_CATEGORIES",
    "TOOL_POISONING_PAPER_ARXIV_ID",
    "audit_insecure_transport",
    "audit_tool_metadata",
    "audit_tool_run_oracles",
    "is_server_audit_finding",
    "run_server_audit",
    "server_audit_paper_evidence",
    "server_audit_report_metadata",
]
