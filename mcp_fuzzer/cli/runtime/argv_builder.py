#!/usr/bin/env python3
"""Pure helper to rebuild inner argv for retries/tests."""

from __future__ import annotations

import sys
from typing import Any


def prepare_inner_argv(args: Any) -> list[str]:
    """Rebuild the argument vector for inner CLI execution."""

    def _get_attr(name: str, default=None):
        if hasattr(args, "__dict__"):
            value = args.__dict__.get(name, default)
            if hasattr(value, "_mock_return_value"):
                return default
            return value
        return getattr(args, name, default)

    def _add_value(flag: str, value):
        if value is None:
            return
        argv.extend([flag, str(value)])

    def _add_bool(flag: str, attr_name: str):
        if _get_attr(attr_name, False):
            argv.append(flag)

    def _add_list(flag: str, values):
        if not values:
            return
        for val in values:
            argv.extend([flag, str(val)])

    argv: list[str] = [sys.argv[0]]

    _add_value("--mode", _get_attr("mode"))
    _add_value("--phase", _get_attr("phase", None))
    _add_value("--protocol-phase", _get_attr("protocol_phase", None))
    _add_value("--protocol", _get_attr("protocol"))
    _add_value("--endpoint", _get_attr("endpoint"))

    _add_value("--tool", _get_attr("tool", None))
    _add_value("--runs", _get_attr("runs", None))
    _add_value("--runs-per-type", _get_attr("runs_per_type", None))
    _add_value("--timeout", _get_attr("timeout", None))
    _add_value("--tool-timeout", _get_attr("tool_timeout", None))
    _add_value("--protocol-type", _get_attr("protocol_type", None))
    _add_value("--spec-resource-uri", _get_attr("spec_resource_uri", None))
    _add_value("--spec-prompt-name", _get_attr("spec_prompt_name", None))
    _add_value("--spec-prompt-args", _get_attr("spec_prompt_args", None))
    _add_value("--fs-root", _get_attr("fs_root", None))
    _add_value("--output-dir", _get_attr("output_dir", None))
    _add_value("--log-level", _get_attr("log_level", None))

    export_safety_data = _get_attr("export_safety_data", None)
    if export_safety_data is not None:
        argv.append("--export-safety-data")
        if export_safety_data:
            argv.append(str(export_safety_data))

    _add_value("--export-csv", _get_attr("export_csv", None))
    _add_value("--export-xml", _get_attr("export_xml", None))
    _add_value("--export-html", _get_attr("export_html", None))
    _add_value("--export-markdown", _get_attr("export_markdown", None))

    _add_value("--output-format", _get_attr("output_format", None))
    _add_list("--output-types", _get_attr("output_types", None))
    _add_value("--output-schema", _get_attr("output_schema", None))
    _add_value("--output-session-id", _get_attr("output_session_id", None))

    _add_bool("--verbose", "verbose")
    _add_bool("--enable-aiomonitor", "enable_aiomonitor")
    _add_bool("--output-compress", "output_compress")
    _add_bool("--enable-safety-system", "enable_safety_system")
    _add_bool("--no-safety", "no_safety")
    _add_bool("--safety-report", "safety_report")
    _add_bool("--retry-with-safety-on-interrupt", "retry_with_safety_on_interrupt")
    _add_bool("--no-network", "no_network")

    if _get_attr("spec_guard", True) is False:
        argv.append("--no-spec-guard")

    _add_list("--allow-host", _get_attr("allow_hosts", None))

    return argv


__all__ = ["prepare_inner_argv"]
