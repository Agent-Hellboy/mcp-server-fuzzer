"""Normalize nested YAML config sections onto flat CLI keys."""

from __future__ import annotations

import argparse
from typing import Any

from ..config import config_mediator


def apply_nested_config_to_args(args: argparse.Namespace, defaults_parser) -> None:
    """Map the nested ``output`` config section onto argparse fields.

    Only the keys the run actually consumes are mapped. ``format``,
    ``compress``, and ``schema`` stay nested-only: the reporter reads them
    straight off the config provider, so there is no CLI field to seed.
    """
    output_section = config_mediator.get("output")
    if isinstance(output_section, dict):
        _apply_if_default(
            args,
            defaults_parser,
            "output_dir",
            output_section.get("directory"),
        )
        if output_section.get("types") is not None:
            _apply_if_default(
                args,
                defaults_parser,
                "output_types",
                output_section.get("types"),
            )


def _apply_if_default(
    args: argparse.Namespace,
    defaults_parser,
    args_key: str,
    config_value: Any,
) -> None:
    if config_value is None:
        return
    default_value = defaults_parser.get_default(args_key)
    if default_value is argparse.SUPPRESS:
        default_value = None
    if getattr(args, args_key, default_value) == default_value:
        setattr(args, args_key, config_value)
