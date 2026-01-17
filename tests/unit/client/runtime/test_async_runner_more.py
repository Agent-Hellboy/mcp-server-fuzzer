import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.client.runtime.async_runner import AsyncRunner


class DummyLoop:
    def __init__(self):
        self.closed = False
        self.calls = []

    def run_until_complete(self, coro):
        self.calls.append(coro)
        try:
            coro.close()
        except Exception:
            pass

    def add_signal_handler(self, *_args, **_kwargs):
        self.calls.append(("signal", _args))

    def close(self):
        self.closed = True


def test_setup_aiomonitor_disables_when_missing(monkeypatch, capsys):
    args = SimpleNamespace(enable_aiomonitor=True)
    runner = AsyncRunner(args, safety=SimpleNamespace())

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.importlib.util.find_spec",
        lambda _name: None,
    )

    runner._setup_aiomonitor()

    assert args.enable_aiomonitor is False
    assert "not installed" in capsys.readouterr().out


def test_setup_aiomonitor_prints_when_present(monkeypatch):
    args = SimpleNamespace(enable_aiomonitor=True)
    runner = AsyncRunner(args, safety=SimpleNamespace())
    calls = []

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.importlib.util.find_spec",
        lambda _name: object(),
    )
    monkeypatch.setattr("builtins.print", lambda *args, **_kwargs: calls.append(args))

    runner._setup_aiomonitor()

    assert any("AIOMonitor enabled" in " ".join(map(str, call)) for call in calls)


def test_setup_signal_handlers_respects_retry_flag():
    args = SimpleNamespace(retry_with_safety_on_interrupt=True)
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()

    runner._setup_signal_handlers()
    assert runner.loop.calls == []


def test_setup_signal_handlers_registers_handlers():
    args = SimpleNamespace(retry_with_safety_on_interrupt=False)
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()

    runner._setup_signal_handlers()

    assert len(runner.loop.calls) == 3


def test_cancel_all_tasks_marks_notice(monkeypatch):
    args = SimpleNamespace()
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = object()

    class DummyConsole:
        def print(self, *_args, **_kwargs):
            return None

    class FakeTask:
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

    tasks = [FakeTask(), FakeTask()]

    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.Console",
        DummyConsole,
    )
    monkeypatch.setattr(
        "mcp_fuzzer.client.runtime.async_runner.asyncio.all_tasks",
        lambda _loop: tasks,
    )

    runner._cancel_all_tasks()

    assert runner._signal_notice_printed is True
    assert all(task.cancelled for task in tasks)


def test_configure_network_policy():
    args = SimpleNamespace(no_network=True, allow_hosts=["example.com"])
    safety = SimpleNamespace(configure_network_policy=MagicMock())
    runner = AsyncRunner(args, safety=safety)

    runner._configure_network_policy()

    safety.configure_network_policy.assert_called_once_with(
        reset_allowed_hosts=True,
        deny_network_by_default=True,
        extra_allowed_hosts=["example.com"],
    )


def test_execute_main_coroutine_without_aiomonitor():
    args = SimpleNamespace(enable_aiomonitor=False)
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()

    async def main():
        return None

    runner._execute_main_coroutine(main)

    assert runner.loop.calls


def test_execute_main_coroutine_with_aiomonitor(monkeypatch):
    args = SimpleNamespace(enable_aiomonitor=True)
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()

    class DummyMonitor:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class DummyModule:
        @staticmethod
        def start_monitor(*_args, **_kwargs):
            return DummyMonitor()

    monkeypatch.setitem(sys.modules, "aiomonitor", DummyModule)

    async def main():
        return None

    runner._execute_main_coroutine(main)
    assert runner.loop.calls


def test_setup_signal_handlers_handles_not_implemented():
    args = SimpleNamespace(retry_with_safety_on_interrupt=False)
    runner = AsyncRunner(args, safety=MagicMock())
    runner.loop = MagicMock()
    runner.loop.add_signal_handler.side_effect = NotImplementedError

    runner._setup_signal_handlers()

    assert runner.loop.add_signal_handler.called
    assert runner.loop.add_signal_handler.call_count == 1


def test_handle_cancellation_sets_exit(capsys):
    args = SimpleNamespace()
    runner = AsyncRunner(args, safety=SimpleNamespace())

    runner._handle_cancellation()

    assert runner.should_exit is True
    assert "Fuzzing interrupted" in capsys.readouterr().out


def test_final_cleanup_restores_argv_and_exit():
    args = SimpleNamespace()
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()
    runner.old_argv = ["old"]
    sys.argv = ["new"]
    runner.should_exit = True

    with pytest.raises(SystemExit):
        runner._final_cleanup()

    assert sys.argv == ["old"]


def test_run_handles_cancelled_error(monkeypatch):
    args = SimpleNamespace()
    runner = AsyncRunner(args, safety=SimpleNamespace())
    runner.loop = DummyLoop()

    monkeypatch.setattr(runner, "_setup_event_loop", lambda: None)
    monkeypatch.setattr(runner, "_is_pytest_environment", lambda: False)
    monkeypatch.setattr(runner, "_setup_aiomonitor", lambda: None)
    monkeypatch.setattr(runner, "_setup_signal_handlers", lambda: None)
    monkeypatch.setattr(runner, "_configure_network_policy", lambda: None)
    monkeypatch.setattr(
        runner,
        "_execute_main_coroutine",
        lambda _main: (_ for _ in ()).throw(asyncio.CancelledError),
    )
    monkeypatch.setattr(runner, "_cleanup_pending_tasks", lambda: None)

    with pytest.raises(SystemExit):
        runner.run(lambda: None, ["mcp-fuzzer"])

    assert runner.should_exit is True
