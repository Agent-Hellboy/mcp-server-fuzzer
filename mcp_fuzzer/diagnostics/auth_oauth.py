"""MCP authentication-security audit checks.

Maps the nine authentication flaw types from "A First Measurement Study on
Authentication Security in Real-World Remote MCP Servers"
(https://arxiv.org/abs/2605.22333) onto black-box checks the fuzzer can run as
an OAuth client against a server's authorization/registration/token endpoints.

Flaw taxonomy (each finding is tagged with its ``flaw_id`` in ``evidence``):
  C1 Dynamic Client Registration
    F1 Malicious DCR Binding      -- AS accepts arbitrary redirect URIs on DCR
    F2 Blind Client Trust         -- AS accepts unknown/unregistered client_id
  C2 Delegated Authorization
    F3 PKCE Layer Inconsistency   -- PKCE not enforced at the token endpoint
    F4 Nested Context Pollution   -- routing data carried in a tamperable state
  C3 Open Client Environment
    F5 PKCE Downgrade             -- AS allows missing code_challenge / plain
    F6 Consent Page Bypass        -- consent page omits the redirect URI
  C4 Common OAuth Misconfigurations
    F7 Open Redirect              -- redirect_uri not validated against registry
    F8 Weak State                 -- AS does not require a state parameter
    F9 Code Replay                -- authorization code reusable after redemption

Read-only checks (default) only GET the authorization endpoint or read
metadata. Intrusive checks (opt-in) register clients / submit redirect URIs and
must only run against servers you are authorized to test.
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

_EVIL_REDIRECT = "https://attacker.example/callback"
_BOGUS_CLIENT_ID = "mcp-fuzzer-unregistered-client-probe"


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


# --- metadata-derived (read-only, reliable) --------------------------------


def audit_as_metadata(as_metadata: Any) -> list[Finding]:
    """F5 (downgrade via metadata) + F3 enforcement note from AS metadata."""
    findings: list[Finding] = []
    methods = list(getattr(as_metadata, "code_challenge_methods_supported", []) or [])
    if "S256" not in methods:
        if "plain" in methods:
            findings.append(
                _finding(
                    "F5", "pkce_downgrade", "high",
                    "Authorization server advertises only the insecure 'plain' "
                    "PKCE method, not S256.",
                    {"code_challenge_methods_supported": methods},
                )
            )
        else:
            findings.append(
                _finding(
                    "F5", "pkce_downgrade", "high",
                    "Authorization server does not advertise PKCE S256 "
                    "(code_challenge_methods_supported missing) -- MCP requires it.",
                    {"code_challenge_methods_supported": methods},
                )
            )
    grants = set(getattr(as_metadata, "grant_types_supported", []) or [])
    insecure = grants & {"implicit", "password"}
    if insecure:
        findings.append(
            _finding(
                "F5", "as_metadata_weakness", "medium",
                f"Authorization server advertises deprecated grant types: "
                f"{sorted(insecure)}.",
                {"grant_types": sorted(insecure)},
            )
        )
    return findings


# --- authorization-endpoint probes (read-only GET) -------------------------


def _authorize(
    http: httpx.Client, authorization_endpoint: str, params: dict[str, str]
) -> tuple[str, str]:
    """GET the authorization endpoint; classify how the AS handled the request.

    Returns ``(kind, detail)`` where kind is ``rejected`` (400/401/403),
    ``redirect`` (3xx -> Location), ``page`` (200 consent/login HTML), or
    ``error``.
    """
    try:
        # Never follow redirects here: F2/F5/F7 classification depends on
        # observing the raw 3xx and its Location header. The shared audit client
        # is created with follow_redirects=True for metadata discovery, so this
        # per-request override is required.
        resp = http.get(
            authorization_endpoint, params=params, follow_redirects=False
        )
    except httpx.HTTPError as exc:
        return "error", str(exc)
    code = resp.status_code
    if code in (301, 302, 303, 307, 308):
        return "redirect", resp.headers.get("location", "")
    if code == 200:
        return "page", resp.text
    if code in (400, 401, 403):
        return "rejected", resp.text[:200]
    return "error", f"HTTP {code}"


def probe_blind_client_trust(
    http: httpx.Client, authorization_endpoint: str, *,
    redirect_uri: str,
) -> list[Finding]:
    """F2: authorize with an unregistered client_id; flag if not rejected."""
    kind, detail = _authorize(
        http, authorization_endpoint,
        {
            "response_type": "code",
            "client_id": _BOGUS_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "state": "probe",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    if kind in ("page", "redirect") and "invalid_client" not in detail:
        return [
            _finding(
                "F2", "blind_client_trust", "high",
                "Authorization server did not reject an unknown/unregistered "
                "client_id (blind client trust -> consent-page spoofing).",
                {"response_kind": kind},
            )
        ]
    return []


def probe_pkce_downgrade_active(
    http: httpx.Client, authorization_endpoint: str, *,
    client_id: str, redirect_uri: str,
) -> list[Finding]:
    """F5: authorize WITHOUT code_challenge; flag if the AS does not reject."""
    kind, detail = _authorize(
        http, authorization_endpoint,
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": "probe",
        },
    )
    if kind in ("page", "redirect") and "invalid_request" not in detail:
        return [
            _finding(
                "F5", "pkce_downgrade", "high",
                "Authorization server accepted an authorization request without "
                "a PKCE code_challenge (PKCE not required).",
                {"response_kind": kind},
            )
        ]
    return []


def probe_weak_state(
    http: httpx.Client, authorization_endpoint: str, *,
    client_id: str, redirect_uri: str,
) -> list[Finding]:
    """F8: authorize WITHOUT a state parameter; flag if the AS does not reject."""
    kind, detail = _authorize(
        http, authorization_endpoint,
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    if kind in ("page", "redirect"):
        return [
            _finding(
                "F8", "weak_state", "info",
                "Authorization server did not enforce a 'state' parameter "
                "(reduced CSRF protection for clients). Note: 'state' is "
                "optional in OAuth 2.0, so most spec-compliant servers do not "
                "reject its absence -- verify the client always sends one.",
                {"response_kind": kind},
            )
        ]
    return []


def probe_open_redirect(
    http: httpx.Client, authorization_endpoint: str, *,
    client_id: str, evil_redirect: str = _EVIL_REDIRECT,
) -> list[Finding]:
    """F7: authorize with an external redirect_uri; flag if the AS redirects to it."""
    kind, detail = _authorize(
        http, authorization_endpoint,
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": evil_redirect,
            "state": "probe",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    if kind == "redirect" and detail.startswith(evil_redirect.split("?")[0]):
        return [
            _finding(
                "F7", "open_redirect", "high",
                "Authorization server redirected to an unregistered external "
                "redirect_uri (open redirect -> code/token theft).",
                {"redirect_location": detail[:200]},
            )
        ]
    return []


def probe_consent_page_bypass(
    http: httpx.Client, authorization_endpoint: str, *,
    client_id: str, redirect_uri: str,
) -> list[Finding]:
    """F6: if a consent page is shown but never displays the redirect_uri."""
    kind, detail = _authorize(
        http, authorization_endpoint,
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": "probe",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    # Only flag a page that actually looks like a consent/authorization screen.
    # A 200 that lacks consent markers is usually a login page (auth required
    # before consent), not a consent page omitting the redirect_uri.
    looks_like_consent = kind == "page" and any(
        marker in detail.lower()
        for marker in ("authorize", "consent", "allow", "grant", "permission")
    )
    if looks_like_consent and redirect_uri not in detail:
        return [
            _finding(
                "F6", "consent_page_bypass", "low",
                "Consent page did not display the redirect_uri (users cannot see "
                "where a code will be sent). Heuristic -- verify manually.",
                {},
            )
        ]
    return []


def inspect_state_for_routing(state: str) -> list[Finding]:
    """F4: a state value that decodes to routing data (URL/host) is tamperable."""
    import base64
    import json
    from urllib.parse import urlsplit

    candidates = [state]
    try:
        padded = state + "=" * (-len(state) % 4)
        candidates.append(base64.urlsafe_b64decode(padded).decode())
    except Exception:
        pass
    for candidate in candidates:
        looks_like_url = candidate.startswith(("http://", "https://"))
        has_routing = False
        try:
            parsed = json.loads(candidate)
            has_routing = isinstance(parsed, dict) and any(
                isinstance(v, str) and urlsplit(v).scheme in ("http", "https")
                for v in parsed.values()
            )
        except (ValueError, TypeError):
            has_routing = False
        if looks_like_url or has_routing:
            return [
                _finding(
                    "F4", "nested_context_pollution", "medium",
                    "Authorization 'state' carries routing data (URL/host) that "
                    "an attacker could tamper to redirect codes.",
                    {},
                )
            ]
    return []


# --- intrusive probes (opt-in: register clients / redeem codes) ------------


def probe_malicious_dcr(
    registration_endpoint: str, *,
    http: httpx.Client,
    evil_redirect: str = _EVIL_REDIRECT,
) -> list[Finding]:
    """F1 + open DCR: register unauthenticated with an attacker redirect URI."""
    from ..auth.oauth.registration import register_dynamic_client
    from ..exceptions import AuthProviderError

    findings: list[Finding] = []
    # Registration must NOT follow redirects: a 307/308 would replay the POST
    # body to a new target. The shared audit client follows redirects, so wrap
    # its transport in a non-redirecting client (this also preserves an injected
    # MockTransport for tests). The wrapper is intentionally not closed -- the
    # transport's lifecycle is owned by the caller's ``http`` client, and
    # closing it here would break later probes that reuse the same transport.
    reg_client = httpx.Client(
        transport=getattr(http, "_transport", None),
        timeout=http.timeout,
        follow_redirects=False,
    )
    try:
        reg = register_dynamic_client(
            registration_endpoint, redirect_uris=[evil_redirect], http=reg_client
        )
    except AuthProviderError:
        return findings  # registration required auth or rejected -> not vulnerable
    except Exception as exc:  # transient/protocol error must not abort the audit
        logger.debug("Malicious DCR probe skipped: %s", exc)
        return findings
    if reg is not None and reg.get("client_id"):
        findings.append(
            _finding(
                "F1", "dcr_malicious_binding", "high",
                "Dynamic client registration accepted an arbitrary external "
                "redirect_uri from an unauthenticated requester (code interception).",
                {"client_id": reg.get("client_id"), "redirect_uri": evil_redirect},
            )
        )
    return findings


def _token_exchange_succeeds(
    token_endpoint: str,
    *,
    http: httpx.Client,
    code: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
    code_verifier: str | None = None,
) -> bool:
    """Return True when the token endpoint returns an access_token."""
    data: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "client_id": client_id,
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    try:
        resp = http.post(
            token_endpoint,
            data=data,
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError:
        return False
    if resp.status_code != 200:
        return False
    try:
        payload = resp.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and bool(payload.get("access_token"))


def probe_pkce_layer_inconsistency(
    token_endpoint: str, *,
    http: httpx.Client,
    code: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
) -> list[Finding]:
    """F3: token endpoint redeems a PKCE-protected code without a code_verifier."""
    if _token_exchange_succeeds(
        token_endpoint,
        http=http,
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        resource=resource,
        code_verifier=None,
    ):
        return [
            _finding(
                "F3", "pkce_layer_inconsistency", "high",
                "Token endpoint accepted an authorization code without a PKCE "
                "code_verifier (PKCE enforced at authorize but not at token).",
                {},
            )
        ]
    return []


def probe_code_replay(
    token_endpoint: str, *,
    http: httpx.Client,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    resource: str,
) -> list[Finding]:
    """F9: redeem the same authorization code twice; flag if both succeed."""
    from ..auth.oauth.authorization_code import exchange_code_for_token

    def _redeem() -> bool:
        try:
            payload = exchange_code_for_token(
                token_endpoint, code=code, code_verifier=code_verifier,
                client_id=client_id, redirect_uri=redirect_uri, resource=resource,
                http=http,
            )
            return bool(payload.get("access_token"))
        except Exception:
            return False

    first = _redeem()
    second = _redeem()
    if first and second:
        return [
            _finding(
                "F9", "code_replay", "high",
                "Authorization code was accepted twice (codes are not single-use).",
                {},
            )
        ]
    return []


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
    """Run flow-dependent checks (F3/F4/F9) after obtaining an auth code.

    F4 inspects the returned ``state`` value. F3 and F9 both redeem the code;
    F3 is tried first; F9 runs only when F3 did not consume the code.
    """
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


# --- orchestrator -----------------------------------------------------------


def run_auth_endpoint_audit(
    as_metadata: Any, *,
    http: httpx.Client,
    redirect_uri: str = "http://127.0.0.1:0/callback",
    client_id: str | None = None,
    intrusive: bool = False,
) -> list[Finding]:
    """Run the authorization-server audit checks against discovered metadata.

    Read-only checks (F5 metadata, F2 blind client trust, F5 active PKCE
    downgrade, F8 weak state, F6 consent bypass) run by default. Intrusive
    checks (F1 malicious DCR, F7 open redirect) run only when ``intrusive`` is
    set. F3/F4/F9 require a completed/consented authorization flow and are
    exposed as standalone helpers for assisted use.
    """
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
