"""MCP authentication-security audit checks.

Maps the nine authentication flaw types from "A First Measurement Study on
Authentication Security in Real-World Remote MCP Servers"
(https://arxiv.org/abs/2605.22333) onto black-box checks the fuzzer can run as
an OAuth client against a server's authorization/registration/token endpoints.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .model import Finding

logger = logging.getLogger(__name__)

AUTH_AUDIT_PAPER_ARXIV_ID = "2605.22333"
AUTH_AUDIT_PAPER_URL = f"https://arxiv.org/abs/{AUTH_AUDIT_PAPER_ARXIV_ID}"
AUTH_AUDIT_PAPER_TITLE = (
    "A First Measurement Study on Authentication Security in "
    "Real-World Remote MCP Servers"
)
AUTH_AUDIT_FLAW_CATEGORIES = frozenset(
    {
        "pkce_downgrade",
        "as_metadata_weakness",
        "blind_client_trust",
        "weak_state",
        "open_redirect",
        "consent_page_bypass",
        "nested_context_pollution",
        "dcr_malicious_binding",
        "code_replay",
        "pkce_layer_inconsistency",
        "unauthenticated_tools",
    }
)


def auth_audit_paper_evidence() -> dict[str, str]:
    """Shared paper citation fields attached to auth-audit findings."""
    return {
        "paper_arxiv_id": AUTH_AUDIT_PAPER_ARXIV_ID,
        "paper_url": AUTH_AUDIT_PAPER_URL,
        "paper_title": AUTH_AUDIT_PAPER_TITLE,
    }


def auth_audit_report_metadata() -> dict[str, str]:
    """Top-level metadata block for findings reports."""
    return auth_audit_paper_evidence()


def is_auth_audit_finding(finding: Finding) -> bool:
    """Return True when a finding comes from the arXiv 2605.22333 audit checks."""
    if finding.kind != "auth":
        return False
    if finding.category in AUTH_AUDIT_FLAW_CATEGORIES:
        return True
    evidence = finding.evidence or {}
    return bool(evidence.get("flaw_id") or evidence.get("paper_finding"))


def _finding(flaw_id: str, category: str, severity: str, detail: str,
             evidence: dict[str, Any] | None = None) -> Finding:
    ev = {"flaw_id": flaw_id, **auth_audit_paper_evidence()}
    if evidence:
        ev.update(evidence)
    return Finding(category, severity, "auth", "authorization_server", None, detail, ev)


def run_post_authorization_audit(
    as_metadata: Any, *,
    http: httpx.Client,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
    oauth_state: str | None = None,
) -> list[Finding]:
    """Run flow-dependent checks (F3/F4/F9) after obtaining an auth code."""
    from .auth_oauth_probes import (
        inspect_state_for_routing,
        probe_code_replay,
        probe_pkce_layer_inconsistency,
    )

    findings: list[Finding] = []
    if oauth_state:
        findings.extend(inspect_state_for_routing(oauth_state))
    token_endpoint = getattr(as_metadata, "token_endpoint", None)
    if not token_endpoint:
        return findings
    pkce_findings = probe_pkce_layer_inconsistency(
        token_endpoint,
        http=http,
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        resource=resource,
    )
    findings.extend(pkce_findings)
    if not pkce_findings:
        findings.extend(
            probe_code_replay(
                token_endpoint,
                http=http,
                code=code,
                code_verifier=code_verifier,
                client_id=client_id,
                redirect_uri=redirect_uri,
                resource=resource,
            )
        )
    return findings


def discover_and_audit_authorization_server(
    endpoint_url: str, *,
    www_authenticate: str | None = None,
    http: httpx.Client,
    redirect_uri: str = "http://127.0.0.1:0/callback",
    client_id: str | None = None,
    intrusive: bool = False,
) -> list[Finding]:
    """Discover RFC 9728/8414 metadata for an MCP endpoint and audit each AS."""
    from ..auth.oauth.canonical import canonical_resource_uri
    from ..auth.oauth.metadata import (
        fetch_authorization_server_metadata,
        fetch_protected_resource_metadata,
    )

    try:
        canonical_resource_uri(endpoint_url)
    except ValueError:
        logger.debug("Auth audit skipped: endpoint is not an absolute URL")
        return []

    prm = fetch_protected_resource_metadata(
        endpoint_url, www_authenticate, http=http
    )
    if prm is None or not prm.authorization_servers:
        logger.debug("Auth audit skipped: no protected-resource metadata")
        return []

    findings: list[Finding] = []
    seen_issuers: set[str] = set()
    for issuer in prm.authorization_servers:
        if issuer in seen_issuers:
            continue
        seen_issuers.add(issuer)
        as_metadata = fetch_authorization_server_metadata(issuer, http=http)
        if as_metadata is None:
            continue
        findings.extend(
            run_auth_endpoint_audit(
                as_metadata,
                http=http,
                redirect_uri=redirect_uri,
                client_id=client_id,
                intrusive=intrusive,
            )
        )
    return findings


def run_auth_endpoint_audit(
    as_metadata: Any, *,
    http: httpx.Client,
    redirect_uri: str = "http://127.0.0.1:0/callback",
    client_id: str | None = None,
    intrusive: bool = False,
) -> list[Finding]:
    """Run the authorization-server audit checks against discovered metadata."""
    from .auth_oauth_probes import (
        _BOGUS_CLIENT_ID,
        audit_as_metadata,
        probe_blind_client_trust,
        probe_consent_page_bypass,
        probe_malicious_dcr,
        probe_open_redirect,
        probe_pkce_downgrade_active,
        probe_weak_state,
    )

    findings: list[Finding] = audit_as_metadata(as_metadata)
    ae = getattr(as_metadata, "authorization_endpoint", None)
    cid = client_id or _BOGUS_CLIENT_ID
    if ae:
        findings += probe_blind_client_trust(http, ae, redirect_uri=redirect_uri)
        findings += probe_pkce_downgrade_active(
            http, ae, client_id=cid, redirect_uri=redirect_uri
        )
        findings += probe_weak_state(http, ae, client_id=cid, redirect_uri=redirect_uri)
        findings += probe_consent_page_bypass(
            http, ae, client_id=cid, redirect_uri=redirect_uri
        )
        if intrusive:
            findings += probe_open_redirect(http, ae, client_id=cid)
    if intrusive:
        reg_ep = getattr(as_metadata, "registration_endpoint", None)
        if reg_ep:
            findings += probe_malicious_dcr(reg_ep, http=http)
    return findings


from .auth_oauth_probes import (  # noqa: E402
    audit_as_metadata,
    inspect_state_for_routing,
    probe_blind_client_trust,
    probe_code_replay,
    probe_consent_page_bypass,
    probe_malicious_dcr,
    probe_open_redirect,
    probe_pkce_downgrade_active,
    probe_pkce_layer_inconsistency,
    probe_weak_state,
)

__all__ = [
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
]
