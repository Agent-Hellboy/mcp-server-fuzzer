#!/usr/bin/env python3
"""
Unit tests for ProtocolMutator.
"""

import inspect
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_fuzzer.fuzz_engine.mutators import ProtocolMutator

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.mutators]


@pytest.fixture
def protocol_mutator():
    """Fixture for ProtocolMutator."""
    return ProtocolMutator()


@pytest.mark.asyncio
async def test_protocol_mutator_init(protocol_mutator):
    """Test ProtocolMutator initialization."""
    assert protocol_mutator is not None
    assert protocol_mutator.strategies is not None


@pytest.mark.asyncio
async def test_get_fuzzer_method_realistic(protocol_mutator):
    """Test getting fuzzer method for realistic phase."""
    method = protocol_mutator.get_fuzzer_method("InitializeRequest", phase="realistic")
    assert method is not None
    assert callable(method)


@pytest.mark.asyncio
async def test_get_fuzzer_method_aggressive(protocol_mutator):
    """Test getting fuzzer method for aggressive phase."""
    method = protocol_mutator.get_fuzzer_method("InitializeRequest", phase="aggressive")
    assert method is not None
    assert callable(method)


@pytest.mark.asyncio
async def test_get_fuzzer_method_unknown_type(protocol_mutator):
    """Test getting fuzzer method for unknown protocol type."""
    method = protocol_mutator.get_fuzzer_method("UnknownType", phase="realistic")
    assert method is None


@pytest.mark.asyncio
async def test_mutate_realistic_phase(protocol_mutator):
    """Test mutation in realistic phase."""
    result = await protocol_mutator.mutate("InitializeRequest", phase="realistic")
    assert isinstance(result, dict)
    assert "jsonrpc" in result or "method" in result or "id" in result


@pytest.mark.asyncio
async def test_mutate_aggressive_phase(protocol_mutator):
    """Test mutation in aggressive phase."""
    result = await protocol_mutator.mutate("InitializeRequest", phase="aggressive")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_default_phase(protocol_mutator):
    """Test mutation with default phase (aggressive)."""
    result = await protocol_mutator.mutate("InitializeRequest")
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_mutate_with_async_method(protocol_mutator):
    """Test mutation with async fuzzer method."""
    with patch.object(
        protocol_mutator.strategies,
        "get_protocol_fuzzer_method",
        return_value=AsyncMock(return_value={"test": "async"}),
    ):
        result = await protocol_mutator.mutate("TestType", phase="realistic")
        assert result == {"test": "async"}


@pytest.mark.asyncio
async def test_mutate_with_sync_method(protocol_mutator):
    """Test mutation with synchronous fuzzer method."""
    sync_method = MagicMock(return_value={"test": "sync"})
    with patch.object(
        protocol_mutator.strategies,
        "get_protocol_fuzzer_method",
        return_value=sync_method,
    ):
        result = await protocol_mutator.mutate("TestType", phase="realistic")
        assert result == {"test": "sync"}


@pytest.mark.asyncio
async def test_mutate_with_phase_parameter(protocol_mutator):
    """Test mutation when method accepts phase parameter."""

    def method_with_phase(phase="aggressive"):
        return {"phase": phase}

    with patch.object(
        protocol_mutator.strategies,
        "get_protocol_fuzzer_method",
        return_value=method_with_phase,
    ):
        result = await protocol_mutator.mutate("TestType", phase="realistic")
        assert result == {"phase": "realistic"}


@pytest.mark.asyncio
async def test_mutate_without_phase_parameter(protocol_mutator):
    """Test mutation when method doesn't accept phase parameter."""

    def method_without_phase():
        return {"no_phase": True}

    with patch.object(
        protocol_mutator.strategies,
        "get_protocol_fuzzer_method",
        return_value=method_without_phase,
    ):
        result = await protocol_mutator.mutate("TestType", phase="realistic")
        assert result == {"no_phase": True}


@pytest.mark.asyncio
async def test_mutate_unknown_protocol_type(protocol_mutator):
    """Test mutation with unknown protocol type raises ValueError."""
    with pytest.raises(ValueError, match="Unknown protocol type"):
        await protocol_mutator.mutate("UnknownType", phase="realistic")


@pytest.mark.asyncio
async def test_mutate_various_protocol_types(protocol_mutator):
    """Test mutation with various protocol types."""
    protocol_types = [
        "ListResourcesRequest",
        "ReadResourceRequest",
        "PingRequest",
        "ListToolsResult",
    ]
    for protocol_type in protocol_types:
        result = await protocol_mutator.mutate(protocol_type, phase="realistic")
        assert isinstance(result, dict)
