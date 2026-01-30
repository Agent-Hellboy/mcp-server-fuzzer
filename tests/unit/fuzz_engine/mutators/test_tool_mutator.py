#!/usr/bin/env python3
"""
Unit tests for ToolMutator.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.mutators import ToolMutator
from mcp_fuzzer.fuzz_engine.mutators import tool_mutator as tool_mutator_module

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


@pytest.fixture
def tool_mutator():
    """Fixture for ToolMutator."""
    return ToolMutator()


@pytest.fixture
def sample_tool():
    """Fixture for a sample tool definition."""
    return {
        "name": "test_tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
            },
        },
    }


@pytest.mark.asyncio
async def test_tool_mutator_init(tool_mutator):
    """Test ToolMutator initialization."""
    assert tool_mutator is not None
    assert tool_mutator.strategies is not None


@pytest.mark.asyncio
async def test_mutate_realistic_phase(tool_mutator, sample_tool):
    """Test mutation in realistic phase."""
    result = await tool_mutator.mutate(sample_tool, phase="realistic")
    assert isinstance(result, dict)
    assert "name" in result or "count" in result or len(result) == 0


@pytest.mark.asyncio
async def test_mutate_aggressive_phase(tool_mutator, sample_tool):
    """Test mutation in aggressive phase."""
    result = await tool_mutator.mutate(sample_tool, phase="aggressive")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_with_empty_tool(tool_mutator):
    """Test mutation with empty tool definition."""
    empty_tool = {"name": "empty_tool"}
    result = await tool_mutator.mutate(empty_tool, phase="realistic")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_with_complex_schema(tool_mutator):
    """Test mutation with complex schema."""
    complex_tool = {
        "name": "complex_tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                },
                "array": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["nested"],
        },
    }
    result = await tool_mutator.mutate(complex_tool, phase="aggressive")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_default_phase(tool_mutator, sample_tool):
    """Test mutation with default phase (aggressive)."""
    result = await tool_mutator.mutate(sample_tool)
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_strategies_integration(tool_mutator, sample_tool):
    """Test that mutator properly delegates to strategies."""
    with patch.object(
        tool_mutator.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
    ) as mock_fuzz:
        mock_fuzz.return_value = {"test": "value"}
        result = await tool_mutator.mutate(sample_tool, phase="realistic")
        mock_fuzz.assert_called_once_with(sample_tool, phase="realistic")
        assert result == {"test": "value"}


def test_record_feedback_adds_seeds(tool_mutator):
    tool_mutator.seed_pool = MagicMock()
    tool_mutator.record_feedback(
        "test_tool",
        {"arg": "value"},
        exception="bad",
        response_signature="sig",
    )
    tool_mutator.seed_pool.add_seed.assert_any_call(
        "test_tool",
        {"arg": "value"},
        signature="exc:bad",
        score=1.5,
    )
    tool_mutator.seed_pool.add_seed.assert_any_call(
        "test_tool",
        {"arg": "value"},
        signature="resp:sig",
        score=1.2,
    )


def test_record_feedback_spec_checks_signature(tool_mutator):
    tool_mutator.seed_pool = MagicMock()
    tool_mutator.record_feedback(
        "test_tool",
        {"arg": "value"},
        exception=None,
        spec_checks=[{"id": "rule-1", "status": "FAIL"}],
    )
    tool_mutator.seed_pool.add_seed.assert_any_call(
        "test_tool",
        {"arg": "value"},
        signature="spec:rule-1",
        score=1.5,
    )


def test_record_feedback_ignores_non_dict(tool_mutator):
    tool_mutator.seed_pool = MagicMock()
    tool_mutator.record_feedback("test_tool", ["not", "dict"])
    tool_mutator.seed_pool.add_seed.assert_not_called()


def test_havoc_stack_bounds(tool_mutator):
    tool_mutator.havoc_mode = True
    tool_mutator.havoc_min = 4
    tool_mutator.havoc_max = 1
    tool_mutator._rng = MagicMock()
    tool_mutator._rng.randint.return_value = 4
    assert tool_mutator._havoc_stack() == 4
    tool_mutator.havoc_mode = False
    assert tool_mutator._havoc_stack() == 1


def test_tool_signature_variants():
    assert tool_mutator_module._tool_signature(
        "oops", None
    ) == "exc:oops"
    assert (
        tool_mutator_module._tool_signature(
            None,
            [
                {"id": "rule-a", "status": "FAIL"},
                {"id": "rule-b", "status": "pass"},
            ],
        )
        == "spec:rule-a"
    )
    assert tool_mutator_module._tool_signature(None, None) is None
