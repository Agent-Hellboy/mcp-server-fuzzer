"""Helpers for MCP authorization metadata discovery."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def _split_header_values(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escape = False

    for char in value:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if char == '"':
            current.append(char)
            in_quotes = not in_quotes
            continue
        if char == "," and not in_quotes:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)

    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def parse_www_authenticate(header: str | Iterable[str] | None) -> list[dict[str, Any]]:
    """Parse one or more WWW-Authenticate header values."""
    if header is None:
        return []

    values = [header] if isinstance(header, str) else [item for item in header if item]
    challenges: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for raw_value in values:
        for part in _split_header_values(raw_value):
            if "=" not in part and " " not in part.strip():
                if current is not None:
                    challenges.append(current)
                current = {"scheme": part.strip(), "params": {}}
                continue

            if current is None:
                scheme, _, remainder = part.partition(" ")
                current = {"scheme": scheme.strip(), "params": {}}
                part = remainder.strip()
                if not part:
                    continue

            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            current["params"][key.strip()] = _unquote(value.strip())

    if current is not None:
        challenges.append(current)

    return challenges


def extract_resource_metadata_url(header: str | Iterable[str] | None) -> str | None:
    """Return the first resource_metadata URL advertised in WWW-Authenticate."""
    for challenge in parse_www_authenticate(header):
        params = challenge.get("params")
        if isinstance(params, dict):
            resource_metadata = params.get("resource_metadata")
            if isinstance(resource_metadata, str) and resource_metadata:
                return resource_metadata
    return None


def extract_requested_scopes(header: str | Iterable[str] | None) -> list[str]:
    """Return the requested scopes advertised in WWW-Authenticate."""
    for challenge in parse_www_authenticate(header):
        params = challenge.get("params")
        if not isinstance(params, dict):
            continue
        scope_value = params.get("scope")
        if isinstance(scope_value, str) and scope_value.strip():
            return [scope for scope in scope_value.split() if scope]
    return []


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def build_protected_resource_metadata_urls(endpoint_url: str) -> list[str]:
    """Build the candidate protected-resource metadata URLs for an MCP endpoint."""
    parsed = urlsplit(endpoint_url)
    path = parsed.path or "/"
    normalized_path = path if path.startswith("/") else f"/{path}"
    trimmed_path = normalized_path.strip("/")

    candidates = []
    if trimmed_path:
        candidates.append(
            urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    f"/.well-known/oauth-protected-resource/{trimmed_path}",
                    "",
                    "",
                )
            )
        )
    candidates.append(
        urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                "/.well-known/oauth-protected-resource",
                "",
                "",
            )
        )
    )
    return _dedupe_preserve_order(candidates)


def build_authorization_server_metadata_urls(issuer_url: str) -> list[str]:
    """Build the candidate authorization-server metadata URLs for an issuer."""
    parsed = urlsplit(issuer_url)
    path = (parsed.path or "").rstrip("/")
    trimmed_path = path.lstrip("/")

    candidates: list[str] = []
    if trimmed_path:
        candidates.extend(
            [
                urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        f"/.well-known/oauth-authorization-server/{trimmed_path}",
                        "",
                        "",
                    )
                ),
                urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        f"/.well-known/openid-configuration/{trimmed_path}",
                        "",
                        "",
                    )
                ),
                urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        f"{path}/.well-known/openid-configuration",
                        "",
                        "",
                    )
                ),
            ]
        )
    else:
        candidates.extend(
            [
                urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        "/.well-known/oauth-authorization-server",
                        "",
                        "",
                    )
                ),
                urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        "/.well-known/openid-configuration",
                        "",
                        "",
                    )
                ),
            ]
        )
    return _dedupe_preserve_order(candidates)


__all__ = [
    "build_authorization_server_metadata_urls",
    "build_protected_resource_metadata_urls",
    "extract_requested_scopes",
    "extract_resource_metadata_url",
    "parse_www_authenticate",
]
