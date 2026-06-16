"""Shared seeded RNG context for fuzz payload generation."""

from __future__ import annotations

import contextvars
import random
from contextlib import contextmanager


_active_rng: contextvars.ContextVar[random.Random | None] = contextvars.ContextVar(
    "fuzz_rng", default=None
)

# Stable process-wide fallback so paths without an active scope keep RNG state
# continuity instead of getting a fresh generator on every access.
_fallback_rng = random.Random()


@contextmanager
def fuzz_rng_scope(rng: random.Random | None):
    """Bind an RNG for fuzz generation within this scope."""
    token = _active_rng.set(rng)
    try:
        yield
    finally:
        _active_rng.reset(token)


def get_fuzz_rng() -> random.Random:
    rng = _active_rng.get()
    return rng if rng is not None else _fallback_rng


class _LazyRng:
    """Delegates attribute access to the active fuzz RNG (patchable in tests)."""

    def __getattr__(self, item: str):
        return getattr(get_fuzz_rng(), item)


lazy_rng = _LazyRng()
