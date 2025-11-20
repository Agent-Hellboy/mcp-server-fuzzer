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
from typing import Protocol

from ..config import (
    SAFETY_LOCAL_HOSTS,
    SAFETY_NO_NETWORK_DEFAULT,
    SAFETY_PROXY_ENV_DENYLIST,
    SAFETY_HEADER_DENYLIST,
)


class SafetyPolicy(Protocol):
    """Protocol for safety policy configuration and checking."""

    def is_host_allowed(
        self,
        url: str,
        allowed_hosts: Iterable[str] | None = None,
        deny_network_by_default: bool | None = None,
    ) -> bool:
        """Check if a host is allowed by policy."""
        ...

    def resolve_redirect_safely(
        self,
        base_url: str,
        location: str | None,
        allowed_hosts: Iterable[str] | None = None,
        deny_network_by_default: bool | None = None,
    ) -> str | None:
        """Resolve a redirect safely."""
        ...

    def sanitize_subprocess_env(
        self,
        source_env: dict[str, str] | None = None,
        proxy_denylist: Iterable[str] | None = None,
    ) -> dict[str, str]:
        """Sanitize environment for subprocess."""
        ...

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize headers."""
        ...

    def configure_network_policy(
        self,
        deny_network_by_default: bool | None = None,
        extra_allowed_hosts: Iterable[str] | None = None,
        reset_allowed_hosts: bool = False,
    ) -> None:
        """Configure network policy."""
        ...


class DefaultSafetyPolicy:
    """Default implementation of safety policy with configurable state."""

    def __init__(self):
        self._deny_network_default_override: bool | None = None
        self._extra_allowed_hosts: set[str] = set()

    def configure_network_policy(
        self,
        deny_network_by_default: bool | None = None,
        extra_allowed_hosts: Iterable[str] | None = None,
        reset_allowed_hosts: bool = False,
    ) -> None:
        """Configure runtime network policy overrides."""
        if deny_network_by_default is not None:
            self._deny_network_default_override = deny_network_by_default

        if reset_allowed_hosts:
            self._extra_allowed_hosts = set()

        if extra_allowed_hosts is not None:
            normalized_hosts = {
                self._normalize_host(h) for h in extra_allowed_hosts if h
            }
            self._extra_allowed_hosts |= {h for h in normalized_hosts if h}

    def _normalize_host(self, host: str) -> str:
        """Normalize host to handle URLs, mixed case, etc."""
        if not host:
            return ""
        s = host.strip().lower()
        # Accept bare host or URL; extract hostname if URL-like
        if "://" in s:
            parsed = urlparse(s)
            host = parsed.hostname or s
        else:
            # For cases like "example.com:80" without protocol
            if ":" in s and not s.startswith("["):
                # Handle IPv6 addresses
                host = s.split(":", 1)[0]
            else:
                host = s
        return host.strip().lower()

    def is_host_allowed(
        self,
        url: str,
        allowed_hosts: Iterable[str] | None = None,
        deny_network_by_default: bool | None = None,
    ) -> bool:
        """Return True if the URL's host is permitted by policy."""
        # Resolve deny flag with runtime override first
        if self._deny_network_default_override is not None:
            deny_network_by_default = self._deny_network_default_override
        elif deny_network_by_default is None:
            deny_network_by_default = SAFETY_NO_NETWORK_DEFAULT
        if not deny_network_by_default:
            return True

        parsed = urlparse(url)
        raw_host = parsed.hostname or ""

        # Normalize the host from the URL
        if not raw_host and ":" in url and not url.startswith("["):
            # Handle non-URL format with port
            parts = url.split(":", 1)
            raw_host = parts[0]

        host = raw_host.lower()

        # Collect and normalize all allowed hosts
        allowed_set = set()
        for h in allowed_hosts or SAFETY_LOCAL_HOSTS:
            # Use same normalization logic
            if "://" in h:
                h_parsed = urlparse(h)
                norm_h = h_parsed.hostname or h
            else:
                norm_h = h.split(":")[0] if ":" in h and not h.startswith("[") else h
            allowed_set.add(norm_h.lower())

        if self._extra_allowed_hosts:
            allowed_set |= self._extra_allowed_hosts

        return host in allowed_set

    def resolve_redirect_safely(
        self,
        base_url: str,
        location: str | None,
        allowed_hosts: Iterable[str] | None = None,
        deny_network_by_default: bool | None = None,
    ) -> str | None:
        """Resolve a redirect target while enforcing same-origin and host allow-list."""
        if not location:
            return None
        resolved = urljoin(base_url, location)
        base = urlparse(base_url)
        new = urlparse(resolved)
        if (new.scheme, new.netloc) != (base.scheme, base.netloc):
            return None
        if not self.is_host_allowed(
            resolved,
            allowed_hosts=allowed_hosts,
            deny_network_by_default=deny_network_by_default,
        ):
            return None
        return resolved

    def sanitize_subprocess_env(
        self,
        source_env: dict[str, str] | None = None,
        proxy_denylist: Iterable[str] | None = None,
    ) -> dict[str, str]:
        """Return an environment mapping safe to pass to subprocesses."""
        env = dict(source_env or os.environ)
        deny = set(proxy_denylist or SAFETY_PROXY_ENV_DENYLIST)
        deny_lower = {k.lower() for k in deny}
        for key in list(env.keys()):
            if key in deny or key.lower() in deny_lower:
                env.pop(key, None)
        return env

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Return a copy of headers with denied keys removed (case-insensitive)."""
        cleaned: dict[str, str] = {}
        deny_lower = {h.lower() for h in SAFETY_HEADER_DENYLIST}
        for key, value in headers.items():
            if key.lower() in deny_lower:
                continue
            cleaned[key] = value
        return cleaned


# Global instance for backward compatibility
_default_policy = DefaultSafetyPolicy()


# Backward compatibility functions that delegate to the default policy
def configure_network_policy(
    deny_network_by_default: bool | None = None,
    extra_allowed_hosts: Iterable[str] | None = None,
    reset_allowed_hosts: bool = False,
) -> None:
    """Configure runtime network policy overrides (backward compatibility)."""
    _default_policy.configure_network_policy(
        deny_network_by_default=deny_network_by_default,
        extra_allowed_hosts=extra_allowed_hosts,
        reset_allowed_hosts=reset_allowed_hosts,
    )


def is_host_allowed(
    url: str,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> bool:
    """Return True if the URL's host is permitted by policy (backward compatibility)."""
    return _default_policy.is_host_allowed(
        url=url,
        allowed_hosts=allowed_hosts,
        deny_network_by_default=deny_network_by_default,
    )


def resolve_redirect_safely(
    base_url: str,
    location: str | None,
    allowed_hosts: Iterable[str] | None = None,
    deny_network_by_default: bool | None = None,
) -> str | None:
    """Resolve a redirect target while enforcing same-origin and host
    allow-list (backward compatibility)."""
    return _default_policy.resolve_redirect_safely(
        base_url=base_url,
        location=location,
        allowed_hosts=allowed_hosts,
        deny_network_by_default=deny_network_by_default,
    )


def sanitize_subprocess_env(
    source_env: dict[str, str] | None = None,
    proxy_denylist: Iterable[str] | None = None,
) -> dict[str, str]:
    """Return an environment mapping safe to pass to subprocesses
    (backward compatibility)."""
    return _default_policy.sanitize_subprocess_env(
        source_env=source_env,
        proxy_denylist=proxy_denylist,
    )


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with denied keys removed (backward compatibility)."""
    return _default_policy.sanitize_headers(headers=headers)


