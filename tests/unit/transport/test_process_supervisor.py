#!/usr/bin/env python3
"""Tests for ProcessSupervisor utilities."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_fuzzer.exceptions import TransportError
from mcp_fuzzer.transport.controller.process_supervisor import ProcessSupervisor


@pytest.mark.asyncio
async def test_apply_backoff_and_reset():
    supervisor = ProcessSupervisor(backoff_base=0.1, backoff_cap=0.15)

    with patch("asyncio.sleep", new=AsyncMock()) as sleep:
        delay = await supervisor.apply_backoff()
        assert delay == 0.1
        sleep.assert_awaited_once_with(0.1)

        delay = await supervisor.apply_backoff()
        assert delay == 0.15
        sleep.assert_awaited_with(0.15)

    assert supervisor.restart_attempts == 2
    supervisor.reset_backoff()
    assert supervisor.restart_attempts == 0


def test_emit_event_handles_observer_error():
    logger = MagicMock()
    supervisor = ProcessSupervisor(logger=logger)
    received = []

    def good_observer(name: str, payload: dict[str, object]) -> None:
        received.append((name, payload))

    def bad_observer(_name: str, _payload: dict[str, object]) -> None:
        raise RuntimeError("boom")

    supervisor.add_observer(bad_observer)
    supervisor.add_observer(good_observer)

    supervisor.emit_event("test", value=1)

    assert received
    assert received[0][0] == "test"
    logger.warning.assert_called_once()


@pytest.mark.asyncio
async def test_read_with_cap_returns_line():
    reader = asyncio.StreamReader()
    reader.feed_data(b"hello\n")
    reader.feed_eof()

    supervisor = ProcessSupervisor(max_read_bytes=1024)
    line = await supervisor.read_with_cap(reader, timeout=0.1)

    assert line == b"hello\n"


@pytest.mark.asyncio
async def test_read_with_cap_timeout(monkeypatch):
    supervisor = ProcessSupervisor()
    reader = asyncio.StreamReader()

    async def _raise_timeout(*_args, **_kwargs):
        raise asyncio.TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", _raise_timeout)
    result = await supervisor.read_with_cap(reader, timeout=0.01)

    assert result is None


@pytest.mark.asyncio
async def test_read_with_cap_empty_returns_none():
    reader = asyncio.StreamReader()
    reader.feed_eof()

    supervisor = ProcessSupervisor()
    result = await supervisor.read_with_cap(reader, timeout=0.1)

    assert result is None


@pytest.mark.asyncio
async def test_read_with_cap_oversized_raises():
    reader = asyncio.StreamReader()
    reader.feed_data(b"toolong\n")
    reader.feed_eof()

    supervisor = ProcessSupervisor(max_read_bytes=4)
    supervisor.state.pid = 42
    events: list[tuple[str, dict[str, object]]] = []

    supervisor.add_observer(lambda name, payload: events.append((name, payload)))

    with pytest.raises(TransportError):
        await supervisor.read_with_cap(reader, timeout=0.1)

    assert events
    assert events[0][0] == "oversized_output"
