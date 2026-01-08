#!/usr/bin/env python3
"""
Metrics Calculator

This module contains logic for calculating fuzzing metrics.
"""

from typing import Any


class MetricsCalculator:
    """Calculates metrics from fuzzing results."""

    def calculate_tool_metrics(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Calculate metrics for tool fuzzing results.

        Args:
            results: List of tool fuzzing results

        Returns:
            Dictionary with calculated metrics
        """
        total = len(results)
        successful = len([r for r in results if r.get("success", False)])
        exceptions = len([r for r in results if not r.get("success", False)])

        return {
            "total": total,
            "successful": successful,
            "exceptions": exceptions,
            "success_rate": successful / total if total > 0 else 0.0,
        }

    def calculate_protocol_metrics(
        self, results: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Calculate metrics for protocol fuzzing results.

        Args:
            results: List of protocol fuzzing results

        Returns:
            Dictionary with calculated metrics
        """
        total = len(results)
        successful = len([r for r in results if r.get("success", False)])
        server_rejections = len(
            [r for r in results if r.get("server_rejected_input", False)]
        )

        return {
            "total": total,
            "successful": successful,
            "server_rejections": server_rejections,
            "success_rate": successful / total if total > 0 else 0.0,
            "rejection_rate": server_rejections / total if total > 0 else 0.0,
        }
