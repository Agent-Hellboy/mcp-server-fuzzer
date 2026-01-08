#!/usr/bin/env python3
"""
Unit tests for ResultCollector.
"""

import pytest

from mcp_fuzzer.fuzz_engine.fuzzerreporter import ResultCollector

pytestmark = [
    pytest.mark.unit,
    pytest.mark.fuzz_engine,
    pytest.mark.fuzzerreporter,
]


@pytest.fixture
def collector():
    """Fixture for ResultCollector."""
    return ResultCollector()


def test_collector_init(collector):
    """Test ResultCollector initialization."""
    assert collector is not None


def test_collect_results_success(collector):
    """Test collecting successful results."""
    batch_results = {
        "results": [
            {"success": True, "run": 1},
            {"success": True, "run": 2},
        ],
        "errors": [],
    }
    results = collector.collect_results(batch_results)
    assert len(results) == 2
    assert all(r["success"] for r in results)


def test_collect_results_with_errors(collector):
    """Test collecting results with errors."""
    batch_results = {
        "results": [{"success": True, "run": 1}],
        "errors": [ValueError("Test error")],
    }
    results = collector.collect_results(batch_results)
    assert len(results) == 2
    assert any("exception" in r for r in results)


def test_collect_results_with_none_values(collector):
    """Test collecting results with None values."""
    batch_results = {
        "results": [{"success": True}, None, {"success": False}],
        "errors": [],
    }
    results = collector.collect_results(batch_results)
    assert len(results) == 2
    assert None not in results


def test_collect_results_empty(collector):
    """Test collecting empty results."""
    batch_results = {"results": [], "errors": []}
    results = collector.collect_results(batch_results)
    assert len(results) == 0


def test_collect_results_missing_keys(collector):
    """Test collecting results with missing keys."""
    batch_results = {"results": [{"success": True}]}
    results = collector.collect_results(batch_results)
    assert len(results) == 1


def test_filter_results_success_only(collector):
    """Test filtering results to show only successful ones."""
    results = [
        {"success": True, "run": 1},
        {"success": False, "run": 2},
        {"success": True, "run": 3},
    ]
    filtered = collector.filter_results(results, success_only=True)
    assert len(filtered) == 2
    assert all(r["success"] for r in filtered)


def test_filter_results_all(collector):
    """Test filtering results to show all."""
    results = [
        {"success": True, "run": 1},
        {"success": False, "run": 2},
    ]
    filtered = collector.filter_results(results, success_only=False)
    assert len(filtered) == 2


def test_filter_results_empty(collector):
    """Test filtering empty results."""
    results = []
    filtered = collector.filter_results(results, success_only=True)
    assert len(filtered) == 0


def test_filter_results_no_success_field(collector):
    """Test filtering results without success field."""
    results = [{"run": 1}, {"run": 2, "success": True}]
    filtered = collector.filter_results(results, success_only=True)
    assert len(filtered) == 1
    assert filtered[0]["success"] is True
