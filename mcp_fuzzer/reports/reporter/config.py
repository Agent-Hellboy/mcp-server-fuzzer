"""Configuration dataclasses for the reporter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class ReporterConfig:
    """Immutable reporter configuration with resolved paths."""

    output_dir: Path
    compress_output: bool
    output_format: str
    output_types: list[str] | None
    output_schema: Any | None

    @classmethod
    def from_provider(
        cls,
        *,
        provider: Mapping[str, Any] | None,
        requested_output_dir: str,
        default_output_dir: str = "reports",
        compress_fallback: bool = False,
    ) -> "ReporterConfig":
        """
        Create a configuration instance using a config provider.

        The provider can override any value under the `output` namespace.
        """

        output_section = provider.get("output", {}) if provider else {}
        raw_dir = requested_output_dir or default_output_dir
        if raw_dir == default_output_dir:
            provider_output_dir = provider.get("output_dir") if provider else None
            raw_dir = provider_output_dir or output_section.get(
                "directory", default_output_dir
            )

        resolved_dir = Path(raw_dir).expanduser()
        compress_output = output_section.get("compress", compress_fallback)
        output_format = output_section.get("format", "json")
        output_types = output_section.get("types")
        output_schema = output_section.get("schema")

        return cls(
            output_dir=resolved_dir,
            compress_output=compress_output,
            output_format=output_format,
            output_types=output_types,
            output_schema=output_schema,
        )
