"""Result collection, building, and metrics for fuzz execution."""

from typing import Any

from ...types import FuzzDataResult


class ResultCollector:
    """Collects and aggregates results from multiple fuzzing runs."""

    def collect_results(
        self, batch_results: dict[str, list[Any]]
    ) -> list[dict[str, Any]]:
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
        if success_only:
            return [r for r in results if r.get("success", False)]
        return results


class ResultBuilder:
    """Builds standardized fuzzing results."""

    def build_tool_result(
        self,
        tool_name: str,
        run_index: int,
        args: dict[str, Any] | None = None,
        original_args: dict[str, Any] | None = None,
        success: bool = True,
        exception: str | None = None,
        safety_blocked: bool = False,
        safety_reason: str | None = None,
        safety_sanitized: bool = False,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool_name": tool_name,
            "run": run_index + 1,
            "success": success,
        }

        result.update(
            {
                key: value
                for key, value in {
                    "args": args,
                    "original_args": original_args,
                    "exception": exception,
                }.items()
                if value is not None
            }
        )

        if safety_blocked:
            result["safety_blocked"] = True
            if safety_reason:
                result["safety_reason"] = safety_reason

        if safety_sanitized:
            result["safety_sanitized"] = safety_sanitized

        return result

    def build_protocol_result(
        self,
        protocol_type: str,
        run_index: int,
        fuzz_data: dict[str, Any],
        server_response: dict[str, Any] | list[dict[str, Any]] | None = None,
        server_error: str | None = None,
        invariant_violations: list[str] | None = None,
        spec_checks: list[dict[str, Any]] | None = None,
        spec_scope: str | None = None,
    ) -> FuzzDataResult:
        result: FuzzDataResult = {
            "protocol_type": protocol_type,
            "run": run_index + 1,
            "fuzz_data": fuzz_data,
            "success": server_error is None and not (invariant_violations or []),
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "invariant_violations": invariant_violations or [],
        }
        if spec_checks is not None:
            result["spec_checks"] = spec_checks
        if spec_scope:
            result["spec_scope"] = spec_scope

        return result

    def build_batch_result(
        self,
        run_index: int,
        batch_request: list[dict[str, Any]],
        server_response: dict[str, Any] | list[dict[str, Any]] | None = None,
        server_error: str | None = None,
        invariant_violations: list[str] | None = None,
    ) -> FuzzDataResult:
        result: FuzzDataResult = {
            "protocol_type": "BatchRequest",
            "run": run_index + 1,
            "fuzz_data": batch_request,
            "success": server_error is None,
            "server_response": server_response,
            "server_error": server_error,
            "server_rejected_input": server_error is not None,
            "batch_size": len(batch_request),
            "invariant_violations": invariant_violations or [],
        }

        return result


class MetricsCalculator:
    """Calculates metrics from fuzzing results."""

    def calculate_tool_metrics(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        total = len(results)
        successful = len([r for r in results if r.get("success", False)])
        exceptions = len(
            [
                r
                for r in results
                if r.get("exception") is not None and not r.get("safety_blocked", False)
            ]
        )

        return {
            "total": total,
            "successful": successful,
            "exceptions": exceptions,
            "success_rate": successful / total if total > 0 else 0.0,
        }

    def calculate_protocol_metrics(
        self, results: list[dict[str, Any]]
    ) -> dict[str, Any]:
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


__all__ = [
    "MetricsCalculator",
    "ResultBuilder",
    "ResultCollector",
]
