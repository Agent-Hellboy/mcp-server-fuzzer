#!/usr/bin/env python3
"""Tests for MCP authentication-security audit checks (arXiv 2605.22333 flaws)."""

from __future__ import annotations

from types import SimpleNamespace

import httpx

from mcp_fuzzer.analysis import (
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
    run_auth_endpoint_audit,
    run_post_authorization_audit,
    discover_and_audit_authorization_server,
)


def _http(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _flaws(findings):
    return {f.evidence["flaw_id"] for f in findings}


_AE = "https://auth.example/authorize"
_RU = "http://127.0.0.1/cb"


def _meta(**kw):
    base = dict(
        code_challenge_methods_supported=["S256"],
        grant_types_supported=["authorization_code"],
        authorization_endpoint=_AE,
        registration_endpoint="https://auth.example/register",
    )
    base.update(kw)
    return SimpleNamespace(**base)


# --- F5 / metadata ----------------------------------------------------------


def test_f5_pkce_downgrade_no_s256():
    findings = audit_as_metadata(_meta(code_challenge_methods_supported=[]))
    assert _flaws(findings) == {"F5"}
    assert findings[0].category == "pkce_downgrade"


def test_f5_pkce_plain_only():
    findings = audit_as_metadata(_meta(code_challenge_methods_supported=["plain"]))
    assert "F5" in _flaws(findings)


def test_metadata_insecure_grants():
    findings = audit_as_metadata(_meta(grant_types_supported=["implicit", "password"]))
    cats = {f.category for f in findings}
    assert "as_metadata_weakness" in cats


def test_metadata_clean_no_findings():
    assert audit_as_metadata(_meta()) == []


# --- F2 blind client trust --------------------------------------------------


def test_f2_blind_client_trust_flagged_when_page_shown():
    with _http(lambda r: httpx.Response(200, text="<html>consent</html>")) as http:
        findings = probe_blind_client_trust(
            http, _AE, redirect_uri=_RU
        )
    assert _flaws(findings) == {"F2"}
    assert findings[0].evidence["paper_url"] == "https://arxiv.org/abs/2605.22333"


def test_f2_no_finding_when_rejected():
    with _http(lambda r: httpx.Response(400, text="invalid_client")) as http:
        findings = probe_blind_client_trust(
            http, _AE, redirect_uri=_RU
        )
    assert findings == []


# --- F5 active PKCE downgrade ----------------------------------------------


def test_f5_active_downgrade_accepted():
    with _http(lambda r: httpx.Response(200, text="page")) as http:
        findings = probe_pkce_downgrade_active(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert _flaws(findings) == {"F5"}


def test_f5_active_rejected():
    with _http(lambda r: httpx.Response(400, text="invalid_request")) as http:
        findings = probe_pkce_downgrade_active(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert findings == []


# --- F8 weak state ----------------------------------------------------------


def test_f8_weak_state_flagged():
    def handler(r):
        return httpx.Response(
            302, headers={"location": "http://127.0.0.1/cb?code=x"}
        )

    with _http(handler) as http:
        findings = probe_weak_state(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert _flaws(findings) == {"F8"}
    # 'state' is optional in OAuth 2.0, so this is informational, not a defect.
    assert findings[0].severity == "info"


# --- F7 open redirect -------------------------------------------------------


def test_f7_open_redirect_flagged():
    def handler(r):
        return httpx.Response(302, headers={"location": "https://attacker.example/callback?code=x"})

    with _http(handler) as http:
        findings = probe_open_redirect(http, _AE, client_id="c")
    assert _flaws(findings) == {"F7"}


def test_f7_no_finding_when_rejected():
    with _http(lambda r: httpx.Response(400, text="invalid redirect_uri")) as http:
        findings = probe_open_redirect(http, _AE, client_id="c")
    assert findings == []


def test_authorize_does_not_follow_redirects_even_on_redirecting_client():
    # The shared audit client uses follow_redirects=True for discovery; the
    # per-request override in _authorize must still surface the raw 3xx so the
    # open-redirect Location is observable (otherwise httpx would chase the
    # redirect and F7 detection would fail).
    def handler(r):
        return httpx.Response(
            302, headers={"location": "https://attacker.example/callback?code=x"}
        )

    http = httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=True
    )
    try:
        findings = probe_open_redirect(http, _AE, client_id="c")
    finally:
        http.close()
    assert _flaws(findings) == {"F7"}


# --- F6 consent page bypass -------------------------------------------------


def test_f6_consent_bypass_when_redirect_absent():
    with _http(
        lambda r: httpx.Response(200, text="<html>Allow this app?</html>")
    ) as http:
        findings = probe_consent_page_bypass(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert _flaws(findings) == {"F6"}
    assert findings[0].severity == "low"  # heuristic; verify manually


def test_f6_no_finding_when_redirect_shown():
    body = "<html>Allow this app? Send code to http://127.0.0.1/cb ?</html>"
    with _http(lambda r: httpx.Response(200, text=body)) as http:
        findings = probe_consent_page_bypass(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert findings == []


def test_f6_no_finding_on_login_page_without_consent_markers():
    # A 200 that is a login page (no consent markers) must not be flagged --
    # it isn't a consent page omitting the redirect_uri.
    body = "<html><form>Username Password Sign in</form></html>"
    with _http(lambda r: httpx.Response(200, text=body)) as http:
        findings = probe_consent_page_bypass(
            http, _AE,
            client_id="c", redirect_uri=_RU,
        )
    assert findings == []


# --- F4 nested context pollution -------------------------------------------


def test_f4_routing_state_url():
    assert _flaws(inspect_state_for_routing("https://evil.example/x")) == {"F4"}


def test_f4_routing_state_json():
    import base64
    import json

    raw = json.dumps({"return": "https://evil.example/x"}).encode()
    token = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert "F4" in _flaws(inspect_state_for_routing(token))


def test_f4_opaque_state_no_finding():
    assert inspect_state_for_routing("aGVsbG8xMjM0NTY") == []


# --- F1 malicious DCR (intrusive) ------------------------------------------


def test_f1_malicious_dcr_binding():
    def handler(r):
        return httpx.Response(201, json={"client_id": "evil-client"})

    with _http(handler) as http:
        findings = probe_malicious_dcr("https://auth.example/register", http=http)
    assert _flaws(findings) == {"F1"}


def test_f1_no_finding_when_registration_denied():
    with _http(lambda r: httpx.Response(401, text="unauthorized")) as http:
        findings = probe_malicious_dcr("https://auth.example/register", http=http)
    assert findings == []


# --- F9 code replay (intrusive) --------------------------------------------


def test_f3_pkce_layer_inconsistency_flagged():
    def handler(r):
        return httpx.Response(200, json={"access_token": "t"})

    with _http(handler) as http:
        findings = probe_pkce_layer_inconsistency(
            "https://auth.example/token", http=http, code="c",
            client_id="cid", redirect_uri=_RU,
            resource="https://mcp.example/mcp",
        )
    assert _flaws(findings) == {"F3"}


def test_f3_no_finding_when_verifier_required():
    with _http(lambda r: httpx.Response(400, text="invalid_grant")) as http:
        findings = probe_pkce_layer_inconsistency(
            "https://auth.example/token", http=http, code="c",
            client_id="cid", redirect_uri=_RU,
            resource="https://mcp.example/mcp",
        )
    assert findings == []


def test_run_post_authorization_audit_f4_and_f3():
    meta = _meta(token_endpoint="https://auth.example/token")

    def handler(r):
        return httpx.Response(200, json={"access_token": "t"})

    with _http(handler) as http:
        findings = run_post_authorization_audit(
            meta, http=http, code="c", code_verifier="v",
            client_id="cid", redirect_uri=_RU,
            resource="https://mcp.example/mcp",
            oauth_state="https://evil.example/x",
        )
    flaws = _flaws(findings)
    assert "F4" in flaws
    assert "F3" in flaws


def test_discover_and_audit_authorization_server():
    def handler(r):
        url = str(r.url)
        if "oauth-protected-resource" in url:
            return httpx.Response(
                200,
                json={"authorization_servers": ["https://auth.example"]},
            )
        if "oauth-authorization-server" in url or "openid-configuration" in url:
            return httpx.Response(
                200,
                json={
                    "token_endpoint": "https://auth.example/token",
                    "authorization_endpoint": _AE,
                    "code_challenge_methods_supported": [],
                },
            )
        if r.url.path == "/authorize":
            return httpx.Response(200, text="<html>consent</html>")
        return httpx.Response(404)

    with _http(handler) as http:
        findings = discover_and_audit_authorization_server(
            "https://mcp.example/mcp", http=http, intrusive=False,
        )
    assert "F5" in _flaws(findings)
    assert "F2" in _flaws(findings)


def test_f9_code_replay_flagged():
    def handler(r):
        return httpx.Response(200, json={"access_token": "t"})

    with _http(handler) as http:
        findings = probe_code_replay(
            "https://auth.example/token", http=http, code="c", code_verifier="v",
            client_id="cid", redirect_uri=_RU,
            resource="https://mcp.example/mcp",
        )
    assert _flaws(findings) == {"F9"}


def test_f9_no_finding_when_second_redemption_fails():
    calls = {"n": 0}

    def handler(r):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"access_token": "t"})
        return httpx.Response(400, text="invalid_grant")

    with _http(handler) as http:
        findings = probe_code_replay(
            "https://auth.example/token", http=http, code="c", code_verifier="v",
            client_id="cid", redirect_uri=_RU,
            resource="https://mcp.example/mcp",
        )
    assert findings == []


# --- orchestrator -----------------------------------------------------------


def test_orchestrator_readonly_vs_intrusive():
    def handler(r):
        if r.url.path == "/register":
            return httpx.Response(201, json={"client_id": "evil"})
        if r.url.path == "/authorize":
            # accepts everything; redirects to whatever redirect_uri is given
            params = dict(r.url.params)
            return httpx.Response(
                302, headers={"location": params.get("redirect_uri", "") + "?code=x"}
            )
        return httpx.Response(404)

    md = _meta(code_challenge_methods_supported=["S256"])
    with _http(handler) as http:
        readonly = run_auth_endpoint_audit(md, http=http, intrusive=False)
        intrusive = run_auth_endpoint_audit(md, http=http, intrusive=True)
    ro = _flaws(readonly)
    intr = _flaws(intrusive)
    assert "F1" not in ro and "F7" not in ro  # intrusive-only not in read-only
    assert {"F1", "F7"} <= intr  # intrusive adds DCR + open redirect
