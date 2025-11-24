#!/usr/bin/env python3
"""Logging setup for CLI entrypoint."""

from __future__ import annotations

import argparse
import logging


def setup_logging(args: argparse.Namespace) -> None:
    """Configure CLI logging with validated level and safe defaults."""

    VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    log_level = getattr(args, "log_level", None)

    if log_level:
        level_name = log_level.upper()
        if level_name not in VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid log level '{log_level}'. "
                f"Valid options: {', '.join(VALID_LOG_LEVELS)}"
            )
        level = getattr(logging, level_name)
    else:
        level = logging.INFO if getattr(args, "verbose", False) else logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,
    )

    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("psutil").setLevel(logging.WARNING)


__all__ = ["setup_logging"]
