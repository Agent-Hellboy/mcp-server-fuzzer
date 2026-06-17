"""Single tool call execution for ToolClient."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..exceptions import ServerCrashError
from ..outcomes import FuzzOutcome, classify_tool_run, is_server_rejection_error
from .. import spec_guard
from ..types import ErrorType, TimeoutScope

from .tool_client_results import (
    build_tool_run_result,
    response_shape_signature,
    tool_timeout_message,
)


class ToolClientExecutionMixin:
    """Run one fuzzed tool call through safety, auth, RPC, and result shaping."""

    _logger: logging.Logger
    safety_system: Any
    auth_manager: Any
    _rpc: Any
    tool_mutator: Any
    transport: Any

    async def _execute_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        label: str | None = None,
        tool_timeout: float | None = None,
    ) -> dict[str, Any]:
        if self.safety_system and self.safety_system.should_skip_tool_call(
            tool_name, args
        ):
            self._logger.warning("Safety system blocked tool call for %s", tool_name)
            return build_tool_run_result(
                args=args,
                label=label,
                success=False,
                safety_blocked=True,
                safety_sanitized=False,
                error=ErrorType.SAFETY_BLOCKED,
            )

        sanitized_args = args
        safety_sanitized = False
        if self.safety_system:
            sanitized_args = self.safety_system.sanitize_tool_arguments(
                tool_name, args
            )
            safety_sanitized = sanitized_args != args

        auth_params = self.auth_manager.get_auth_params_for_tool(tool_name)

        args_for_call = {**sanitized_args}
        if auth_params:
            args_for_call.update(auth_params)

        try:
            result = await self._call_tool(
                tool_name, args_for_call, tool_timeout=tool_timeout
            )
            spec_checks = spec_guard.check_tool_result_content(result)
            response_signature = response_shape_signature(result)
            self.tool_mutator.record_feedback(
                tool_name,
                sanitized_args,
                spec_checks=spec_checks,
                response_signature=response_signature,
            )
            success, outcome = classify_tool_run(result=result)
            call_result = build_tool_run_result(
                args=sanitized_args,
                label=label,
                success=success,
                safety_blocked=False,
                safety_sanitized=safety_sanitized,
                result=result,
                spec_checks=spec_checks,
                spec_scope="tool_result" if spec_checks else None,
                outcome=outcome,
                accepted_malformed=outcome == FuzzOutcome.ACCEPTED_MALFORMED,
            )
        except asyncio.TimeoutError:
            exception = tool_timeout_message(tool_timeout)
            self._logger.warning("Tool %s call timed out: %s", tool_name, exception)
            self.tool_mutator.record_feedback(
                tool_name,
                sanitized_args,
                exception=exception,
            )
            call_result = build_tool_run_result(
                args=sanitized_args,
                label=label,
                success=False,
                safety_blocked=False,
                safety_sanitized=safety_sanitized,
                error=ErrorType.TOOL_TIMEOUT,
                exception=exception,
                timeout_scope=TimeoutScope.CALL,
            )
        except Exception as e:
            self._logger.warning("Exception calling tool %s: %s", tool_name, e)
            self.tool_mutator.record_feedback(
                tool_name, sanitized_args, exception=str(e)
            )
            crash = None
            if isinstance(e, ServerCrashError):
                success, outcome = False, FuzzOutcome.CRASHED
                error = ErrorType.SERVER_CRASHED
                crash = dict(getattr(e, "context", None) or {})
                self._logger.error(
                    "Server CRASHED while fuzzing tool %s: %s", tool_name, crash
                )
            elif is_server_rejection_error(e):
                success, outcome = True, FuzzOutcome.SERVER_REJECTED
                error = None
            else:
                success, outcome = classify_tool_run(exception=e)
                error = ErrorType.TOOL_CALL_FAILED
            call_result = build_tool_run_result(
                args=sanitized_args,
                label=label,
                success=success,
                safety_blocked=False,
                safety_sanitized=safety_sanitized,
                error=error,
                exception=str(e) if not success else None,
                outcome=outcome,
                crash=crash,
            )

        rss = self._sample_server_memory()
        if rss is not None:
            call_result["rss_bytes"] = rss
        return call_result

    def _sample_server_memory(self) -> int | None:
        """Best-effort RSS sample of the server process (stdio targets only)."""
        sampler = getattr(self.transport, "sample_server_memory", None)
        if callable(sampler):
            try:
                return sampler()
            except Exception:
                return None
        return None

    async def _call_tool(
        self,
        tool_name: str,
        args_for_call: dict[str, Any],
        *,
        tool_timeout: float | None = None,
    ) -> Any:
        if tool_timeout is None:
            return await self._rpc.call_tool(tool_name, args_for_call)
        return await asyncio.wait_for(
            self._rpc.call_tool(tool_name, args_for_call),
            timeout=tool_timeout,
        )

    async def _process_fuzz_results(
        self,
        tool_name: str,
        fuzz_results: list[dict[str, Any]],
        *,
        tool_timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        processed = []
        for fuzz_result in fuzz_results:
            args = fuzz_result["args"]
            processed.append(
                await self._execute_tool_call(
                    tool_name,
                    args,
                    label=f"tool:{tool_name}",
                    tool_timeout=tool_timeout,
                )
            )
        return processed
