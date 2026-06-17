#!/usr/bin/env python3
"""Session bootstrap: wire transport, safety, reporter, client, and context."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from ..client.fuzzer_client import MCPFuzzerClient
from ..corpus import build_corpus_root, build_target_id, default_fs_root
from ..orchestrator.models import SessionContext
from ..reports import FuzzerReporter
from ..safety_system.safety import SafetyFilter
from ..transport.bootstrap import TransportBuildRequest, build_driver_with_auth
from .session_settings import SessionSettings


@dataclass
class SessionBundle:
    """Wired components for a single fuzz session."""

    transport: Any
    client: MCPFuzzerClient
    reporter: FuzzerReporter | None
    context: SessionContext
    build_transport_request: Callable[[dict[str, Any]], TransportBuildRequest]


class SessionBootstrap:
    """Build transport, safety, reporter, client, and session context."""

    def __init__(self, settings: SessionSettings) -> None:
        self._settings = settings

    @staticmethod
    def build_transport_request(config: dict[str, Any]) -> TransportBuildRequest:
        return TransportBuildRequest(
            protocol=config["protocol"],
            endpoint=config["endpoint"],
            timeout=config.get("timeout", 30.0),
            transport_retries=config.get("transport_retries", 1),
            transport_retry_delay=config.get("transport_retry_delay", 0.5),
            transport_retry_backoff=config.get("transport_retry_backoff", 2.0),
            transport_retry_max_delay=config.get("transport_retry_max_delay", 5.0),
            transport_retry_jitter=config.get("transport_retry_jitter", 0.1),
            auth_manager=config.get("auth_manager"),
            safety_enabled=config.get("safety_enabled", True),
        )

    def build(self) -> SessionBundle:
        config = self._settings.config
        transport = build_driver_with_auth(self.build_transport_request(config))

        safety_system = None
        if self._settings.safety_enabled:
            safety_system = SafetyFilter()
            fs_root = config.get("fs_root")
            if fs_root:
                try:
                    safety_system.set_fs_root(fs_root)
                except Exception as exc:  # pragma: no cover
                    logging.warning(
                        "Failed to set filesystem root '%s': %s", fs_root, exc
                    )

        reporter = None
        if self._settings.output_dir is not None:
            reporter = FuzzerReporter(
                output_dir=self._settings.output_dir, safety_system=safety_system
            )

        corpus_root = None
        if config.get("corpus_enabled", True):
            target_id = build_target_id(
                self._settings.protocol, self._settings.endpoint
            )
            fs_root = config.get("fs_root") or str(default_fs_root())
            corpus_root = str(build_corpus_root(fs_root, target_id))

        client = MCPFuzzerClient(
            transport=transport,
            auth_manager=self._settings.auth_manager,
            tool_timeout=config.get("tool_timeout"),
            reporter=reporter,
            safety_system=safety_system,
            safety_enabled=self._settings.safety_enabled,
            max_concurrency=config.get("max_concurrency", 5),
            corpus_root=corpus_root,
            havoc_mode=config.get("havoc_mode", False),
            seed=config.get("seed"),
        )
        reporter = client.reporter
        if reporter is not None:
            reporter.set_fuzzing_metadata(
                mode=config.get("mode", "unknown"),
                protocol=config.get("protocol", "unknown"),
                endpoint=config.get("endpoint", "unknown"),
                runs=config.get("runs", 0),
                runs_per_type=config.get("runs_per_type"),
            )

        context = SessionContext(
            client=client,
            config=config,
            reporter=reporter,
            protocol_phase=self._settings.protocol_phase,
        )
        return SessionBundle(
            transport=transport,
            client=client,
            reporter=reporter,
            context=context,
            build_transport_request=self.build_transport_request,
        )


__all__ = ["SessionBootstrap", "SessionBundle"]
