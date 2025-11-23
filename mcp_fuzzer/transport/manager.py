import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from ..exceptions import TransportError


@dataclass
class TransportProcessState:
    """Lightweight state container for a transport-managed process."""

    pid: int | None = None
    started_at: float | None = None
    exited_at: float | None = None
    restart_count: int = 0
    last_signal: str | None = None
    last_error: str | None = None
    last_stdout_tail: str | None = None
    last_stderr_tail: str | None = None

    def record_start(self, pid: int | None) -> None:
        self.pid = pid
        self.started_at = time.time()
        self.exited_at = None

    def record_exit(self) -> None:
        self.exited_at = time.time()

    def record_restart(self) -> None:
        self.restart_count += 1

    def record_signal(self, signal_type: str) -> None:
        self.last_signal = signal_type

    def record_error(self, error: str) -> None:
        self.last_error = error

    def record_stdout_tail(self, text: str) -> None:
        self.last_stdout_tail = text

    def record_stderr_tail(self, text: str) -> None:
        self.last_stderr_tail = text


class TransportManager:
    """Small helper to unify transport process state, backoff, and logging hooks."""

    def __init__(
        self,
        *,
        max_read_bytes: int = 256 * 1024,
        backoff_base: float = 0.2,
        backoff_cap: float = 2.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.state = TransportProcessState()
        self._observers: list[Callable[[str, dict[str, Any]], None]] = []
        self._max_read_bytes = max_read_bytes
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._restart_attempts = 0
        self._logger = logger or logging.getLogger(__name__)

    @property
    def restart_attempts(self) -> int:
        return self._restart_attempts

    def add_observer(self, callback: Callable[[str, dict[str, Any]], None]) -> None:
        self._observers.append(callback)

    def emit_event(self, name: str, **payload: Any) -> None:
        data = {"event": name, **payload}
        for cb in self._observers:
            try:
                cb(name, data)
            except Exception:
                self._logger.debug("Observer callback failed", exc_info=True)
        self._logger.debug("[transport] %s: %s", name, payload)

    async def apply_backoff(self) -> float:
        """Apply exponential backoff between restarts."""
        self._restart_attempts += 1
        delay = min(
            self._backoff_base * (2 ** (self._restart_attempts - 1)), self._backoff_cap
        )
        if delay > 0:
            await asyncio.sleep(delay)
        return delay

    def reset_backoff(self) -> None:
        self._restart_attempts = 0

    async def read_with_cap(
        self,
        reader: asyncio.StreamReader,
        timeout: float | None = None,
    ) -> bytes | None:
        """Read a newline-delimited message with a size cap."""
        buf = bytearray()
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            except asyncio.TimeoutError:
                return None

            if not chunk:
                return None

            buf.extend(chunk)
            if b"\n" in chunk:
                break

            if len(buf) > self._max_read_bytes:
                self.emit_event(
                    "oversized_output",
                    pid=self.state.pid,
                    size=len(buf),
                    limit=self._max_read_bytes,
                )
                raise TransportError(
                    "Received oversized message from stdio transport",
                    context={"size": len(buf), "limit": self._max_read_bytes},
                )

        return bytes(buf)
