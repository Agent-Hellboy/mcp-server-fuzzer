#!/usr/bin/env python3
"""
Unit tests for BatchMutator.
"""

import pytest
from unittest.mock import MagicMock, patch

from mcp_fuzzer.fuzz_engine.mutators import BatchMutator

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


@pytest.fixture
def batch_mutator():
    """Fixture for BatchMutator."""
    return BatchMutator()


@pytest.mark.asyncio
async def test_batch_mutator_init(batch_mutator):
    """Test BatchMutator initialization."""
    assert batch_mutator is not None
    assert batch_mutator.strategies is not None


@pytest.mark.asyncio
async def test_mutate_without_protocol_types(batch_mutator):
    """Test batch mutation without specifying protocol types."""
    result = await batch_mutator.mutate(phase="realistic")
    assert result is None or isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_with_protocol_types(batch_mutator):
    """Test batch mutation with specific protocol types."""
    protocol_types = ["InitializeRequest", "ListResourcesRequest"]
    result = await batch_mutator.mutate(
        protocol_types=protocol_types, phase="aggressive"
    )
    assert result is None or isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_realistic_phase(batch_mutator):
    """Test batch mutation in realistic phase."""
    result = await batch_mutator.mutate(phase="realistic")
    assert result is None or isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_aggressive_phase(batch_mutator):
    """Test batch mutation in aggressive phase."""
    result = await batch_mutator.mutate(phase="aggressive")
    assert result is None or isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_default_phase(batch_mutator):
    """Test batch mutation with default phase (aggressive)."""
    result = await batch_mutator.mutate()
    assert result is None or isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_strategies_integration(batch_mutator):
    """Test that mutator properly delegates to strategies."""
    mock_batch = [{"jsonrpc": "2.0", "id": 1, "method": "test"}]
    with patch.object(
        batch_mutator.strategies,
        "generate_batch_request",
        return_value=mock_batch,
    ) as mock_generate:
        result = await batch_mutator.mutate(
            protocol_types=["TestType"], phase="realistic"
        )
        mock_generate.assert_called_once_with(
            protocol_types=["TestType"], phase="realistic"
        )
        assert result == mock_batch


@pytest.mark.asyncio
async def test_mutate_with_empty_protocol_types(batch_mutator):
    """Test batch mutation with empty protocol types list."""
    result = await batch_mutator.mutate(protocol_types=[], phase="realistic")
    assert result == []
    assert isinstance(result, list)


@pytest.mark.asyncio
async def test_mutate_with_many_protocol_types(batch_mutator):
    """Test batch mutation with many protocol types."""
    protocol_types = [
        "InitializeRequest",
        "ListResourcesRequest",
        "ReadResourceRequest",
        "PingRequest",
    ]
    result = await batch_mutator.mutate(
        protocol_types=protocol_types, phase="aggressive"
    )
    assert result is None or isinstance(result, list)
