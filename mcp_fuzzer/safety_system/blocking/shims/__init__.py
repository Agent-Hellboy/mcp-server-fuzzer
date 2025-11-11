#!/usr/bin/env python3
"""Utility helpers for loading reusable command-blocker shim templates."""

from __future__ import annotations

from importlib import resources


def load_shim_template(name: str) -> str:
    """Return the contents of the shim template with the given filename."""
    template_path = resources.files(__name__).joinpath(name)
    return template_path.read_text()


__all__ = ["load_shim_template"]
