import pytest

from mcp_fuzzer.client.runtime.run_plan import RunContext, build_run_plan


class DummyReporter:
    def __init__(self):
        self.calls = []

    def add_spec_checks(self, checks):
        self.calls.append(("add", checks))

    def print_spec_guard_summary(
        self,
        checks,
        requested_version=None,
        negotiated_version=None,
    ):
        self.calls.append(("print", checks, requested_version, negotiated_version))


class DummyClient:
    def __init__(self):
        self.calls = []

    async def run_spec_suite(self, **_):
        self.calls.append("spec")
        return [{"id": "x", "status": "PASS"}]

    async def fuzz_all_tools(self, **_):
        self.calls.append("tools")
        return {"t": []}

    async def fuzz_all_protocol_types(self, **_):
        self.calls.append("protocol")
        return {"p": []}

    async def fuzz_stateful_sequences(self, **_):
        self.calls.append("stateful")
        return []

    async def fuzz_resources(self, **_):
        self.calls.append("resources")
        return {"r": []}

    async def fuzz_prompts(self, **_):
        self.calls.append("prompts")
        return {"p": []}


@pytest.mark.asyncio
async def test_run_plan_all_mode_executes_steps():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "all", "spec_guard": True, "stateful": True}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("all", config)
    await plan.execute(context)
    assert "tools" in client.calls
    assert "spec" in client.calls
    assert "protocol" in client.calls
    assert "stateful" in client.calls
    assert context.tool_results == {"t": []}
    assert context.protocol_results.get("p") == []


@pytest.mark.asyncio
async def test_run_plan_tools_mode_only_runs_tools():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "tools", "spec_guard": True, "stateful": True}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("tools", config)
    await plan.execute(context)
    assert client.calls == ["tools"]
    assert context.tool_results == {"t": []}


@pytest.mark.asyncio
async def test_run_plan_protocol_mode_only_runs_protocol():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "protocol", "spec_guard": True, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("protocol", config)
    await plan.execute(context)
    assert client.calls == ["spec", "protocol"]
    assert context.protocol_results == {"p": []}


@pytest.mark.asyncio
async def test_run_plan_resources_mode_only_runs_resources():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "resources", "spec_guard": True, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("resources", config)
    await plan.execute(context)
    assert client.calls == ["spec", "resources"]
    assert context.protocol_results == {"r": []}


@pytest.mark.asyncio
async def test_run_plan_prompts_mode_only_runs_prompts():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "prompts", "spec_guard": True, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("prompts", config)
    await plan.execute(context)
    assert client.calls == ["spec", "prompts"]
    assert context.protocol_results == {"p": []}


@pytest.mark.asyncio
async def test_run_plan_stateful_disabled_skips_stateful():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "protocol", "spec_guard": True, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("protocol", config)
    await plan.execute(context)
    assert "stateful" not in client.calls


@pytest.mark.asyncio
async def test_run_plan_spec_guard_disabled_skips_checks():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "protocol", "spec_guard": False, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("protocol", config)
    await plan.execute(context)
    assert "spec" not in client.calls
    assert reporter.calls == []


@pytest.mark.asyncio
async def test_run_plan_spec_guard_enabled_records_checks():
    client = DummyClient()
    reporter = DummyReporter()
    config = {"mode": "protocol", "spec_guard": True, "stateful": False}
    context = RunContext(
        client=client,
        config=config,
        reporter=reporter,
        protocol_phase="realistic",
    )
    plan = build_run_plan("protocol", config)
    await plan.execute(context)
    assert "spec" in client.calls
    assert reporter.calls
