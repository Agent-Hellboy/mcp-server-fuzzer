#!/usr/bin/env python3
"""Logging setup for CLI entrypoint."""

from __future__ import annotations

import argparse
import logging


def setup_logging(args: argparse.Namespace) -> None:

    VALID_LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]    
    if getattr(args, "log_level", None) and args.log_level.upper() in VALID_LOG_LEVELS:
        level = getattr(logging, args.log_level.upper())
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
