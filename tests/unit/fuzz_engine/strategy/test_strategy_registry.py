import pytest

from mcp_fuzzer.fuzz_engine.mutators.strategies import (
    ProtocolStrategies,
    ToolStrategies,
    strategy_registry,
)


def test_strategy_registry_protocol_override():
    def custom_protocol():
        return {"jsonrpc": "2.0", "method": "custom"}

    strategy_registry.register_protocol(
        "InitializeRequest",
        "realistic",
        custom_protocol,
    )
    try:
        method = ProtocolStrategies.get_protocol_fuzzer_method(
            "InitializeRequest", "realistic"
        )
        assert method is custom_protocol
    finally:
        strategy_registry.unregister_protocol("InitializeRequest", "realistic")


@pytest.mark.asyncio
async def test_strategy_registry_tool_override():
    async def custom_tool(_tool):
        return {"overridden": True}

    strategy_registry.register_tool("aggressive", custom_tool)
    try:
        result = await ToolStrategies.fuzz_tool_arguments({"name": "x"}, "aggressive")
        assert result == {"overridden": True}
    finally:
        strategy_registry.unregister_tool("aggressive")
