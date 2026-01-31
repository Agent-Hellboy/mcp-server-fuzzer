#!/usr/bin/env python3
"""Retry wrapper for transport drivers."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
from typing import Any, AsyncIterator

from ...exceptions import PayloadValidationError, TransportError
from ..interfaces.driver import TransportDriver


@dataclass(frozen=True)
class RetryPolicy:
    """Simple retry policy for transport requests."""

    max_attempts: int = 1
    base_delay: float = 0.5
    max_delay: float = 5.0
    backoff_factor: float = 2.0
    jitter: float = 0.1

    def clamp(self) -> "RetryPolicy":
        attempts = max(1, int(self.max_attempts))
        return RetryPolicy(
            max_attempts=attempts,
            base_delay=max(0.0, float(self.base_delay)),
            max_delay=max(0.0, float(self.max_delay)),
            backoff_factor=max(1.0, float(self.backoff_factor)),
            jitter=max(0.0, float(self.jitter)),
        )


class RetryingTransport(TransportDriver):
    """Transport wrapper that retries transient failures."""

    def __init__(
        self,
        transport: TransportDriver,
        *,
        policy: RetryPolicy | None = None,
        retry_on: tuple[type[BaseException], ...] = (TransportError,),
    ) -> None:
        self._transport = transport
        self._policy = (policy or RetryPolicy()).clamp()
        self._retry_on = retry_on

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - passthrough
        return getattr(self._transport, name)

    def _should_retry(self, exc: BaseException) -> bool:
        if isinstance(exc, PayloadValidationError):
            return False
        return isinstance(exc, self._retry_on)

    def _next_delay(self, attempt: int) -> float:
        delay = self._policy.base_delay * (self._policy.backoff_factor ** (attempt - 1))
        delay = min(delay, self._policy.max_delay)
        if self._policy.jitter:
            jitter = delay * self._policy.jitter
            delay += random.uniform(-jitter, jitter)
        return max(delay, 0.0)

    async def _with_retries(self, coro_factory, label: str) -> Any:
        attempts = self._policy.max_attempts
        for attempt in range(1, attempts + 1):
            try:
                return await coro_factory()
            except Exception as exc:  # noqa: BLE001 - intentional retry boundary
                if not self._should_retry(exc) or attempt >= attempts:
                    raise
                await asyncio.sleep(self._next_delay(attempt))
        raise TransportError(f"Retry wrapper failed for {label}")

    async def send_request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> Any:
        return await self._with_retries(
            lambda: self._transport.send_request(method, params),
            "send_request",
        )

    async def send_raw(self, payload: dict[str, Any]) -> Any:
        return await self._with_retries(
            lambda: self._transport.send_raw(payload),
            "send_raw",
        )

    async def send_notification(
        self, method: str, params: dict[str, Any] | None = None
    ) -> None:
        await self._with_retries(
            lambda: self._transport.send_notification(method, params),
            "send_notification",
        )

    async def send_batch_request(
        self, batch: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        if hasattr(self._transport, "send_batch_request"):
            return await self._with_retries(
                lambda: self._transport.send_batch_request(batch),
                "send_batch_request",
            )
        raise AttributeError("Underlying transport has no send_batch_request")

    async def connect(self) -> None:
        if hasattr(self._transport, "connect"):
            await self._with_retries(lambda: self._transport.connect(), "connect")

    async def disconnect(self) -> None:
        if hasattr(self._transport, "disconnect"):
            await self._transport.disconnect()

    async def _stream_request(
        self, payload: dict[str, Any]
    ) -> AsyncIterator[dict[str, Any]]:
        async for item in self._transport.stream_request(payload):
            yield item
