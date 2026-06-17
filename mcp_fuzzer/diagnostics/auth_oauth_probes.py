"""Individual OAuth authorization-server probe functions."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .model import Finding

logger = logging.getLogger(__name__)

_EVIL_REDIRECT = "https://attacker.example/callback"
_BOGUS_CLIENT_ID = "mcp-fuzzer-unregistered-client-probe"


def _finding(flaw_id: str, category: str, severity: str, detail: str,
             evidence: dict[str, Any] | None = None) -> Finding:
    from .auth_oauth import auth_audit_paper_evidence

    ev = {"flaw_id": flaw_id, **auth_audit_paper_evidence()}
    if evidence:
        ev.update(evidence)
    return Finding(category, severity, "auth", "authorization_server", None, detail, ev)


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


def _authorize(
    http: httpx.Client, authorization_endpoint: str, params: dict[str, str]
) -> tuple[str, str]:
    """GET the authorization endpoint; classify how the AS handled the request."""
    try:
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


def probe_malicious_dcr(
    registration_endpoint: str, *,
    http: httpx.Client,
    evil_redirect: str = _EVIL_REDIRECT,
) -> list[Finding]:
    """F1 + open DCR: register unauthenticated with an attacker redirect URI."""
    from ..auth.oauth.registration import register_dynamic_client
    from ..exceptions import AuthProviderError

    findings: list[Finding] = []
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
        return findings
    except Exception as exc:
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


__all__ = [
    "_BOGUS_CLIENT_ID",
    "audit_as_metadata",
    "inspect_state_for_routing",
    "probe_blind_client_trust",
    "probe_code_replay",
    "probe_consent_page_bypass",
    "probe_malicious_dcr",
    "probe_open_redirect",
    "probe_pkce_downgrade_active",
    "probe_pkce_layer_inconsistency",
    "probe_weak_state",
]
