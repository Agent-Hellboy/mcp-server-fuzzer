"""PKCE (Proof Key for Code Exchange, RFC 7636) helpers.

The MCP authorization spec requires clients to implement PKCE with the
``S256`` challenge method when technically capable (OAuth 2.1 Section 4.1.1).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass


def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class PKCEChallenge:
    """A generated PKCE verifier/challenge pair."""

    verifier: str
    challenge: str
    method: str = "S256"


def generate_pkce(n_bytes: int = 32) -> PKCEChallenge:
    """Generate a PKCE ``code_verifier`` / ``code_challenge`` pair (S256).

    The verifier is a high-entropy URL-safe string (43-128 chars per
    RFC 7636 Section 4.1); the challenge is ``BASE64URL(SHA256(verifier))``.
    """
    # 32 random bytes -> 43-char base64url verifier (within the 43-128 range).
    verifier = _b64url_no_pad(secrets.token_bytes(max(32, n_bytes)))
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = _b64url_no_pad(digest)
    return PKCEChallenge(verifier=verifier, challenge=challenge, method="S256")
