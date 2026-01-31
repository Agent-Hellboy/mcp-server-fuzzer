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
