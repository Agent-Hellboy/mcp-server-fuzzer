#!/usr/bin/env python3
"""
Unit tests for MetricsCalculator.
"""

import pytest

from mcp_fuzzer.fuzz_engine.fuzzerreporter import MetricsCalculator

pytestmark = [
    pytest.mark.unit,
    pytest.mark.fuzz_engine,
    pytest.mark.fuzzerreporter,
]


@pytest.fixture
def metrics_calculator():
    """Fixture for MetricsCalculator."""
    return MetricsCalculator()


def test_metrics_calculator_init(metrics_calculator):
    """Test MetricsCalculator initialization."""
    assert metrics_calculator is not None


def test_calculate_tool_metrics_all_success(metrics_calculator):
    """Test calculating metrics for all successful tool runs."""
    results = [
        {"success": True, "run": 1},
        {"success": True, "run": 2},
        {"success": True, "run": 3},
    ]
    metrics = metrics_calculator.calculate_tool_metrics(results)
    assert metrics["total"] == 3
    assert metrics["successful"] == 3
    assert metrics["exceptions"] == 0
    assert metrics["success_rate"] == 1.0


def test_calculate_tool_metrics_all_failure(metrics_calculator):
    """Test calculating metrics for all failed tool runs."""
    results = [
        {"success": False, "run": 1},
        {"success": False, "run": 2},
    ]
    metrics = metrics_calculator.calculate_tool_metrics(results)
    assert metrics["total"] == 2
    assert metrics["successful"] == 0
    assert metrics["exceptions"] == 2
    assert metrics["success_rate"] == 0.0


def test_calculate_tool_metrics_mixed(metrics_calculator):
    """Test calculating metrics for mixed tool runs."""
    results = [
        {"success": True, "run": 1},
        {"success": False, "run": 2},
        {"success": True, "run": 3},
    ]
    metrics = metrics_calculator.calculate_tool_metrics(results)
    assert metrics["total"] == 3
    assert metrics["successful"] == 2
    assert metrics["exceptions"] == 1
    assert metrics["success_rate"] == pytest.approx(2 / 3)


def test_calculate_tool_metrics_empty(metrics_calculator):
    """Test calculating metrics for empty results."""
    results = []
    metrics = metrics_calculator.calculate_tool_metrics(results)
    assert metrics["total"] == 0
    assert metrics["successful"] == 0
    assert metrics["exceptions"] == 0
    assert metrics["success_rate"] == 0.0


def test_calculate_protocol_metrics_all_success(metrics_calculator):
    """Test calculating metrics for all successful protocol runs."""
    results = [
        {"success": True, "server_rejected_input": False},
        {"success": True, "server_rejected_input": False},
    ]
    metrics = metrics_calculator.calculate_protocol_metrics(results)
    assert metrics["total"] == 2
    assert metrics["successful"] == 2
    assert metrics["server_rejections"] == 0
    assert metrics["success_rate"] == 1.0
    assert metrics["rejection_rate"] == 0.0


def test_calculate_protocol_metrics_with_rejections(metrics_calculator):
    """Test calculating metrics for protocol runs with rejections."""
    results = [
        {"success": True, "server_rejected_input": False},
        {"success": False, "server_rejected_input": True},
        {"success": False, "server_rejected_input": True},
    ]
    metrics = metrics_calculator.calculate_protocol_metrics(results)
    assert metrics["total"] == 3
    assert metrics["successful"] == 1
    assert metrics["server_rejections"] == 2
    assert metrics["success_rate"] == pytest.approx(1 / 3)
    assert metrics["rejection_rate"] == pytest.approx(2 / 3)


def test_calculate_protocol_metrics_empty(metrics_calculator):
    """Test calculating metrics for empty protocol results."""
    results = []
    metrics = metrics_calculator.calculate_protocol_metrics(results)
    assert metrics["total"] == 0
    assert metrics["successful"] == 0
    assert metrics["server_rejections"] == 0
    assert metrics["success_rate"] == 0.0
    assert metrics["rejection_rate"] == 0.0


def test_calculate_protocol_metrics_no_rejection_field(metrics_calculator):
    """Test calculating metrics when rejection field is missing."""
    results = [
        {"success": True},
        {"success": False},
    ]
    metrics = metrics_calculator.calculate_protocol_metrics(results)
    assert metrics["server_rejections"] == 0
