"""Auth and security audit CLI arguments."""

from __future__ import annotations

import argparse


def add_audit_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-config",
        help="Path to authentication configuration file (JSON format)",
    )
    parser.add_argument(
        "--auth-env",
        action="store_true",
        help="Load authentication from environment variables",
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help=(
            "Authenticate against the MCP server's OAuth 2.1 authorization server "
            "(MCP 2025-11-25 spec): discovers RFC 9728/8414 metadata and obtains a "
            "bearer token. Used with --endpoint."
        ),
    )
    parser.add_argument(
        "--oauth-grant",
        choices=["authorization_code", "client_credentials"],
        default="authorization_code",
        help=(
            "OAuth grant to use: 'authorization_code' (PKCE, browser-based, "
            "user-delegated) or 'client_credentials' (machine-to-machine)."
        ),
    )
    parser.add_argument(
        "--oauth-client-id",
        help="Pre-registered OAuth client_id (skips dynamic registration).",
    )
    parser.add_argument(
        "--oauth-client-secret",
        help="OAuth client_secret for confidential clients.",
    )
    parser.add_argument(
        "--oauth-scope",
        help="OAuth scope(s) to request (space-separated).",
    )
    parser.add_argument(
        "--oauth-client-id-metadata-url",
        help=(
            "HTTPS URL of a Client ID Metadata Document to use as the client_id."
        ),
    )
    parser.add_argument(
        "--oauth-open-browser",
        action="store_true",
        help=(
            "Auto-open the default browser for the authorization-code flow. "
            "Off by default for unattended fuzzing -- the URL is printed instead. "
            "(For fully non-interactive runs, prefer "
            "--oauth-grant client_credentials.)"
        ),
    )
    parser.add_argument(
        "--oauth-no-token-cache",
        action="store_true",
        help=(
            "Disable the on-disk OAuth token cache. By default the token is "
            "cached so the browser authorization step happens at most once."
        ),
    )
    parser.add_argument(
        "--fail-if-no-tools",
        action="store_true",
        help=(
            "Exit non-zero (code 2) when no tools could be fuzzed (e.g. the "
            "server returned no tools, auth was required, or the endpoint was "
            "unreachable). Useful in CI/registry sweeps where exit 0 with "
            "'no tools available' is easy to misread as success. Enabled "
            "automatically when MCP_FUZZER_CI or MCP_FUZZER_IN_DOCKER is set."
        ),
    )
    parser.add_argument(
        "--allow-empty-tools",
        action="store_true",
        help=(
            "Do not auto-enable --fail-if-no-tools in Docker/CI even when no "
            "tools are discovered. For hub sweeps that may legitimately expose "
            "zero tools on a fixture."
        ),
    )
    parser.add_argument(
        "--auth-audit",
        action="store_true",
        help=(
            "Run MCP OAuth authorization-security audit checks (arXiv "
            "2605.22333): metadata review, authorization-endpoint probes, and "
            "unauthenticated tool exposure when auth is advertised. Requires an "
            "HTTP/SSE remote endpoint."
        ),
    )
    parser.add_argument(
        "--auth-audit-intrusive",
        action="store_true",
        help=(
            "Include intrusive auth-audit probes (dynamic client registration "
            "with attacker redirect URIs, open-redirect tests). Only use "
            "against servers you are authorized to test."
        ),
    )
    parser.add_argument(
        "--security-audit",
        action="store_true",
        help=(
            "Run MCP tool-security audit checks (arXiv 2503.23278 / 2509.06572): "
            "tool/schema poisoning markers, tool shadowing, dangerous capability "
            "combos, cleartext transport, and active injection oracles on fuzz "
            "outputs (command/path/SQL/output prompt injection)."
        ),
    )
