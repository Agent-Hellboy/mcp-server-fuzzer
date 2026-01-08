#!/usr/bin/env python3
"""
Unit tests for ResultBuilder.
"""

import pytest

from mcp_fuzzer.fuzz_engine.fuzzerreporter import ResultBuilder

pytestmark = [
    pytest.mark.unit,
    pytest.mark.fuzz_engine,
    pytest.mark.fuzzerreporter,
]


@pytest.fixture
def result_builder():
    """Fixture for ResultBuilder."""
    return ResultBuilder()


def test_result_builder_init(result_builder):
    """Test ResultBuilder initialization."""
    assert result_builder is not None


def test_build_tool_result_success(result_builder):
    """Test building a successful tool result."""
    result = result_builder.build_tool_result(
        tool_name="test_tool",
        run_index=0,
        args={"param": "value"},
        success=True,
    )
    assert result["tool_name"] == "test_tool"
    assert result["run"] == 1
    assert result["success"] is True
    assert result["args"] == {"param": "value"}


def test_build_tool_result_failure(result_builder):
    """Test building a failed tool result."""
    result = result_builder.build_tool_result(
        tool_name="test_tool",
        run_index=1,
        success=False,
        exception="Test error",
    )
    assert result["tool_name"] == "test_tool"
    assert result["run"] == 2
    assert result["success"] is False
    assert result["exception"] == "Test error"


def test_build_tool_result_with_safety_blocked(result_builder):
    """Test building a tool result with safety blocking."""
    result = result_builder.build_tool_result(
        tool_name="dangerous_tool",
        run_index=0,
        args={"command": "rm -rf /"},
        success=False,
        safety_blocked=True,
        safety_reason="Dangerous operation",
    )
    assert result["safety_blocked"] is True
    assert result["safety_reason"] == "Dangerous operation"


def test_build_tool_result_with_safety_sanitized(result_builder):
    """Test building a tool result with sanitized arguments."""
    result = result_builder.build_tool_result(
        tool_name="test_tool",
        run_index=0,
        args={"safe": "value"},
        original_args={"unsafe": "value"},
        success=True,
        safety_sanitized=True,
    )
    assert result["safety_sanitized"] is True
    assert result["args"] == {"safe": "value"}
    assert result["original_args"] == {"unsafe": "value"}


def test_build_tool_result_without_optional_fields(result_builder):
    """Test building a tool result without optional fields."""
    result = result_builder.build_tool_result(
        tool_name="test_tool", run_index=0, success=True
    )
    assert "args" not in result
    assert "exception" not in result
    assert "safety_blocked" not in result
    assert "safety_sanitized" not in result


def test_build_protocol_result_success(result_builder):
    """Test building a successful protocol result."""
    fuzz_data = {"jsonrpc": "2.0", "method": "test"}
    server_response = {"jsonrpc": "2.0", "result": "ok"}
    result = result_builder.build_protocol_result(
        protocol_type="TestRequest",
        run_index=0,
        fuzz_data=fuzz_data,
        server_response=server_response,
    )
    assert result["protocol_type"] == "TestRequest"
    assert result["run"] == 1
    assert result["success"] is True
    assert result["fuzz_data"] == fuzz_data
    assert result["server_response"] == server_response
    assert result["server_rejected_input"] is False


def test_build_protocol_result_failure(result_builder):
    """Test building a failed protocol result."""
    fuzz_data = {"jsonrpc": "2.0", "method": "test"}
    result = result_builder.build_protocol_result(
        protocol_type="TestRequest",
        run_index=1,
        fuzz_data=fuzz_data,
        server_error="Invalid request",
    )
    assert result["success"] is False
    assert result["server_error"] == "Invalid request"
    assert result["server_rejected_input"] is True


def test_build_protocol_result_with_invariant_violations(result_builder):
    """Test building a protocol result with invariant violations."""
    violations = ["Missing jsonrpc field", "Invalid id type"]
    result = result_builder.build_protocol_result(
        protocol_type="TestRequest",
        run_index=0,
        fuzz_data={},
        invariant_violations=violations,
    )
    assert result["invariant_violations"] == violations


def test_build_protocol_result_with_empty_invariant_violations(result_builder):
    """Test building a protocol result with empty invariant violations."""
    result = result_builder.build_protocol_result(
        protocol_type="TestRequest",
        run_index=0,
        fuzz_data={},
        invariant_violations=None,
    )
    assert result["invariant_violations"] == []


def test_build_batch_result_success(result_builder):
    """Test building a successful batch result."""
    batch_request = [
        {"jsonrpc": "2.0", "id": 1, "method": "test1"},
        {"jsonrpc": "2.0", "id": 2, "method": "test2"},
    ]
    server_response = [
        {"jsonrpc": "2.0", "id": 1, "result": "ok1"},
        {"jsonrpc": "2.0", "id": 2, "result": "ok2"},
    ]
    result = result_builder.build_batch_result(
        run_index=0,
        batch_request=batch_request,
        server_response=server_response,
    )
    assert result["protocol_type"] == "BatchRequest"
    assert result["run"] == 1
    assert result["success"] is True
    assert result["batch_size"] == 2
    assert result["fuzz_data"] == batch_request
    assert result["server_response"] == server_response


def test_build_batch_result_failure(result_builder):
    """Test building a failed batch result."""
    batch_request = [{"jsonrpc": "2.0", "id": 1, "method": "test"}]
    result = result_builder.build_batch_result(
        run_index=0,
        batch_request=batch_request,
        server_error="Batch processing failed",
    )
    assert result["success"] is False
    assert result["server_error"] == "Batch processing failed"
    assert result["server_rejected_input"] is True
    assert result["batch_size"] == 1


def test_build_batch_result_with_invariant_violations(result_builder):
    """Test building a batch result with invariant violations."""
    batch_request = [{"jsonrpc": "2.0", "id": 1, "method": "test"}]
    violations = ["Response ID mismatch", "Missing result field"]
    result = result_builder.build_batch_result(
        run_index=0,
        batch_request=batch_request,
        invariant_violations=violations,
    )
    assert result["invariant_violations"] == violations


def test_build_batch_result_empty_batch(result_builder):
    """Test building a batch result with empty batch."""
    result = result_builder.build_batch_result(run_index=0, batch_request=[])
    assert result["batch_size"] == 0
