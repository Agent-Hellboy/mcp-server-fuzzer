"""Tests for async runtime helpers."""

import asyncio
import sys
from types import SimpleNamespace
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from mcp_fuzzer.client.runtime.async_runner import execute_inner_client, AsyncRunner
from mcp_fuzzer.client.runtime.retry import run_with_retry_on_interrupt
from mcp_fuzzer.client.safety import SafetyController


def _make_aiomonitor():
    @contextmanager
    def _start_monitor(loop, console_enabled=True, locals=True):
        yield

    return SimpleNamespace(start_monitor=_start_monitor)


def test_execute_inner_client_with_aiomonitor(monkeypatch):
    args = MagicMock(
        retry_with_safety_on_interrupt=False,
        no_network=False,
        allow_hosts=None,
        enable_aiomonitor=True,
    )
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "")
    monkeypatch.setitem(sys.modules, "aiomonitor", _make_aiomonitor())
    fake_loop = asyncio.new_event_loop()

    async def dummy():
        return None

    with (
        patch("asyncio.new_event_loop", return_value=fake_loop),
        patch("asyncio.set_event_loop"),
        patch.object(fake_loop, "add_signal_handler"),
        patch.object(fake_loop, "run_until_complete"),
    ):
        execute_inner_client(args, dummy, ["prog"])


def test_execute_inner_client_handles_cancel(monkeypatch):
    args = MagicMock(
        retry_with_safety_on_interrupt=False,
        no_network=True,
        allow_hosts=None,
        enable_aiomonitor=False,
    )
    loop = asyncio.new_event_loop()

    def _run_until_complete(_):
        raise asyncio.CancelledError()

    with (
        patch("asyncio.new_event_loop", return_value=loop),
        patch("asyncio.set_event_loop"),
        patch.object(SafetyController, "configure_network_policy"),
        patch.object(loop, "add_signal_handler"),
        patch.object(loop, "run_until_complete", side_effect=_run_until_complete),
    ):
        try:

            async def dummy():
                return None

            execute_inner_client(args, dummy, ["prog"])
        except SystemExit as exc:
            assert exc.code == 130
    loop.close()


def test_async_runner_disables_aiomonitor_when_missing(monkeypatch):
    args = MagicMock(enable_aiomonitor=True)
    runner = AsyncRunner(args, SafetyController())

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.importlib.util.find_spec",
        lambda name: None,
    )

    runner._setup_aiomonitor()

    assert args.enable_aiomonitor is False


def test_async_runner_cleanup_pending_tasks_timeout(monkeypatch):
    args = MagicMock()
    runner = AsyncRunner(args, SafetyController())
    loop = asyncio.new_event_loop()
    runner.loop = loop

    mock_task = MagicMock()
    mock_task.done.return_value = False

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.asyncio.all_tasks",
        lambda _loop: {mock_task},
    )
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.asyncio.gather",
        lambda *args, **kwargs: object(),
    )
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.asyncio.wait_for",
        lambda *args, **kwargs: (_ for _ in ()).throw(asyncio.TimeoutError()),
    )

    runner._cleanup_pending_tasks()

    assert mock_task.cancel.call_count >= 1
    loop.close()


def test_run_with_retry_on_interrupt_exits_when_no_retry(monkeypatch):
    args = MagicMock(enable_safety_system=False, retry_with_safety_on_interrupt=False)
    with (
        patch(
            "mcp_fuzzer.client.runtime.retry.execute_inner_client",
            side_effect=KeyboardInterrupt,
        ),
        patch("mcp_fuzzer.client.runtime.retry.Console") as mock_console,
    ):
        with pytest.raises(SystemExit) as exc:
            run_with_retry_on_interrupt(args, lambda: None, ["prog"])
        assert exc.value.code == 130
    mock_console.return_value.print.assert_called_once()
