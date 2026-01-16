#!/usr/bin/env python3
"""
Result Collector

This module contains logic for collecting and aggregating fuzzing results.
"""

from typing import Any


class ResultCollector:
    """Collects and aggregates results from multiple fuzzing runs."""

    def collect_results(
        self, batch_results: dict[str, list[Any]]
    ) -> list[dict[str, Any]]:
        """
        Collect results from batch execution.

        Args:
            batch_results: Dictionary with 'results' and 'errors' lists

        Returns:
            List of collected results
        """
        results = [
            result for result in batch_results.get("results", []) if result is not None
        ]
        results.extend(
            {"exception": str(error), "success": False}
            for error in batch_results.get("errors", [])
            if error is not None
        )
        return results

    def filter_results(
        self, results: list[dict[str, Any]], success_only: bool = False
    ) -> list[dict[str, Any]]:
        """
        Filter results based on success status.

        Args:
            results: List of results to filter
            success_only: If True, only return successful results

        Returns:
            Filtered list of results
        """
        if success_only:
            return [r for r in results if r.get("success", False)]
        return results
