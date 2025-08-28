#!/usr/bin/env python3
"""
Modular safety policy helpers focused on containment and external-reference blocking.

This module centralizes simple, deterministic checks so transports and runtime
can enforce safety consistently without duplicating logic.
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Set
from urllib.parse import urljoin, urlparse
import os

from ..config import (
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_PROXY_ENV_DENYLIST,
    SAFETY_HEADER_DENYLIST,
)

_POLICY_DENY_NETWORK_DEFAULT_OVERRIDE: Optional[bool] = None
_POLICY_EXTRA_ALLOWED_HOSTS: Set[str] = set()


def configure_network_policy(
    deny_network_by_default: Optional[bool] = None,
    extra_allowed_hosts: Optional[Iterable[str]] = None,
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
        _POLICY_EXTRA_ALLOWED_HOSTS |= {h for h in extra_allowed_hosts if h}


def is_host_allowed(
    url: str,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> bool:
    """Return True if the URL's host is permitted by policy.

    - By default, only localhost/loopback hosts are allowed.
    - If deny_network_by_default is False, allow any host.
    """
    # Resolve deny flag with runtime override first
    if _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE is not None:
        deny_network_by_default = _POLICY_DENY_NETWORK_DEFAULT_OVERRIDE
    elif deny_network_by_default is None:
        deny_network_by_default = SAFETY_NO_NETWORK_DEFAULT
    if not deny_network_by_default:
        return True

    parsed = urlparse(url)
    host = parsed.hostname or ""
    hosts = set(allowed_hosts or SAFETY_LOCAL_HOSTS)
    if _POLICY_EXTRA_ALLOWED_HOSTS:
        hosts |= _POLICY_EXTRA_ALLOWED_HOSTS
    return host in hosts


def resolve_redirect_safely(
    base_url: str,
    location: str | None,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> str | None:
    """Resolve a redirect target while enforcing same-origin and host allow-list.

    Returns the resolved URL if allowed, otherwise None.
    """
    if not location:
        return None
    resolved = urljoin(base_url, location)
    base = urlparse(base_url)
    new = urlparse(resolved)
    if (new.scheme, new.netloc) != (base.scheme, base.netloc):
        return None
    if not is_host_allowed(
        resolved,
        allowed_hosts=allowed_hosts,
        deny_network_by_default=deny_network_by_default,
    ):
        return None
    return resolved


def sanitize_subprocess_env(
    source_env: Dict[str, str] | None = None,
    proxy_denylist: Iterable[str] | None = None,
) -> Dict[str, str]:
    """Return an environment mapping safe to pass to subprocesses.

    Removes proxy-related environment variables to avoid accidental egress via proxies.
    """
    env = dict(source_env or os.environ)
    deny = set(proxy_denylist or SAFETY_PROXY_ENV_DENYLIST)
    deny_lower = {k.lower() for k in deny}
    for key in list(env.keys()):
        if key in deny or key.lower() in deny_lower:
            env.pop(key, None)
    return env


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of headers with denied keys removed (case-insensitive)."""
    cleaned: Dict[str, str] = {}
    deny_lower = {h.lower() for h in SAFETY_HEADER_DENYLIST}
    for key, value in headers.items():
        if key.lower() in deny_lower:
            continue
        cleaned[key] = value
    return cleaned
