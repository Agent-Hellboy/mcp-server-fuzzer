#!/usr/bin/env python3
"""
Modular safety policy helpers focused on containment and external-reference blocking.

This module centralizes simple, deterministic checks so transports and runtime
can enforce safety consistently without duplicating logic.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse
import os
from collections.abc import Iterable

# Import constants directly from config (constants are values, not behavior)
# Behavior (functions/classes) should go through client mediator
from ..config.constants import (
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_PROXY_ENV_DENYLIST,
    SAFETY_HEADER_DENYLIST,
)

_POLICY_DENY_NETWORK_DEFAULT_OVERRIDE: bool | None = None
_POLICY_EXTRA_ALLOWED_HOSTS: set[str] = set()


def _normalize_host(host: str | None) -> str:
    """Normalize hostnames for policy comparisons."""
    if not host:
        return ""

    s = host.strip().lower()
    if not s:
        return ""

    # Accept full URLs and use parsed hostname when available.
    if "://" in s:
        parsed = urlparse(s)
        normalized = parsed.hostname or s
    # Handle bracketed IPv6 with optional port: [::1]:8080 -> ::1
    elif s.startswith("["):
        end = s.find("]")
        if end != -1:
            normalized = s[1:end]
        else:
            normalized = s.strip("[]")
    # Handle host:port without protocol.
    elif s.count(":") == 1:
        normalized = s.split(":", 1)[0]
    # Bare IPv6 literals contain multiple colons and should not be split.
    elif ":" in s:
        normalized = s
    else:
        normalized = s

    return normalized.strip().lower().rstrip(".")


def _normalized_host_set(hosts: Iterable[str]) -> frozenset[str]:
    """Normalize an iterable of hosts, dropping any that normalize to empty."""
    return frozenset(
        normalized for h in hosts if h and (normalized := _normalize_host(h))
    )


# Normalized forms of the module-level policy constants. Both sit on a
# per-request path -- is_host_allowed and sanitize_headers run for every
# outbound request from every driver -- and neither constant is mutated or
# patched anywhere, so they are computed once at import instead of on each
# call. An explicit allowlist/denylist argument is still normalized per call.
_DEFAULT_ALLOWED_HOSTS = _normalized_host_set(SAFETY_LOCAL_HOSTS)
_DEFAULT_HEADER_DENY_LOWER = frozenset(h.lower() for h in SAFETY_HEADER_DENYLIST)
_DEFAULT_PROXY_ENV_DENY = frozenset(SAFETY_PROXY_ENV_DENYLIST)
_DEFAULT_PROXY_ENV_DENY_LOWER = frozenset(k.lower() for k in _DEFAULT_PROXY_ENV_DENY)


def configure_network_policy(
    deny_network_by_default: bool | None = None,
    extra_allowed_hosts: Iterable[str] | None = None,
    reset_allowed_hosts: bool = False,
) -> None:
    """Configure runtime network policy overrides.

    - deny_network_by_default: when True, only local hosts are allowed.
    - extra_allowed_hosts: additional hostnames to permit.
    - reset_allowed_hosts: when True, clear any previously added hosts.
    """
    global _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE
    global _POLICY_EXTRA_ALLOWED_HOSTS

    if deny_network_by_default is not None:
        _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE = deny_network_by_default

    if reset_allowed_hosts:
        _POLICY_EXTRA_ALLOWED_HOSTS = set()

    if extra_allowed_hosts is not None:
        normalized_hosts = {_normalize_host(h) for h in extra_allowed_hosts if h}
        _POLICY_EXTRA_ALLOWED_HOSTS |= {h for h in normalized_hosts if h}


def is_host_allowed(
    url: str,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> bool:
    """Return True if the URL's host is permitted by policy.

    - When deny_network_by_default is True, only allowed hosts are permitted.
    - When deny_network_by_default is False, allow any host.
    """
    # Resolve deny flag with runtime override first
    if _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE is not None:
        deny_network_by_default = _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE
    elif deny_network_by_default is None:
        deny_network_by_default = SAFETY_NO_NETWORK_DEFAULT
    if not deny_network_by_default:
        return True

    parsed = urlparse(url)
    raw_host = parsed.hostname or ""
    if not raw_host:
        raw_host = url.split("/", 1)[0] if "://" not in url else url

    host = _normalize_host(raw_host)

    # Collect and normalize all allowed hosts. The default list is pre-normalized;
    # an explicit (truthy) allowed_hosts is normalized here, matching the previous
    # `allowed_hosts or SAFETY_LOCAL_HOSTS` fallback semantics exactly.
    if allowed_hosts:
        allowed_set = _normalized_host_set(allowed_hosts)
    else:
        allowed_set = _DEFAULT_ALLOWED_HOSTS

    if _POLICY_EXTRA_ALLOWED_HOSTS:
        allowed_set |= _POLICY_EXTRA_ALLOWED_HOSTS

    return host in allowed_set


def resolve_redirect_safely(
    base_url: str,
    location: str | None,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> str | None:
    """Resolve a redirect target while enforcing host allow-list policy.

    Returns the resolved URL if allowed, otherwise None.
    """
    if not location:
        return None
    resolved = urljoin(base_url, location)
    if not is_host_allowed(
        resolved,
        allowed_hosts=allowed_hosts,
        deny_network_by_default=deny_network_by_default,
    ):
        return None
    return resolved


def sanitize_subprocess_env(
    source_env: dict[str, str] | None = None,
    proxy_denylist: Iterable[str] | None = None,
) -> dict[str, str]:
    """Return an environment mapping safe to pass to subprocesses.

    Removes proxy-related environment variables to avoid accidental egress via proxies.
    """
    env = dict(source_env or os.environ)
    if proxy_denylist:
        deny = set(proxy_denylist)
        deny_lower = {k.lower() for k in deny}
    else:
        deny = _DEFAULT_PROXY_ENV_DENY
        deny_lower = _DEFAULT_PROXY_ENV_DENY_LOWER
    for key in list(env.keys()):
        if key in deny or key.lower() in deny_lower:
            env.pop(key, None)
    return env


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with denied keys removed (case-insensitive)."""
    cleaned: dict[str, str] = {}
    deny_lower = _DEFAULT_HEADER_DENY_LOWER
    for key, value in headers.items():
        if key.lower() in deny_lower:
            continue
        cleaned[key] = value
    return cleaned
