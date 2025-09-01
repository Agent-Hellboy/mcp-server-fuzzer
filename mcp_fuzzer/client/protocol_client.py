#!/usr/bin/env python3
"""
Protocol Client Module

This module provides functionality for fuzzing MCP protocol types.
"""

import json
import logging
import traceback
from typing import Any, Dict, List, Optional

from ..types import ProtocolFuzzResult, SafetyCheckResult, PREVIEW_LENGTH

from ..fuzz_engine.fuzzer.protocol_fuzzer import ProtocolFuzzer
from ..safety_system.safety import SafetyProvider


class ProtocolClient:
    """Client for fuzzing MCP protocol types."""

    def __init__(
        self,
        transport,
        safety_system: Optional[SafetyProvider] = None,
        max_concurrency: int = 5,
    ):
        """
        Initialize the protocol client.

        Args:
            transport: Transport protocol for server communication
            safety_system: Safety system for filtering operations
            max_concurrency: Maximum number of concurrent operations
        """
        self.transport = transport
        self.safety_system = safety_system
        # Important: let ProtocolClient own sending (safety checks happen here)
        self.protocol_fuzzer = ProtocolFuzzer(None, max_concurrency=max_concurrency)
        self._logger = logging.getLogger(__name__)

    async def _check_safety_for_protocol_message(
        self, protocol_type: str, fuzz_data: Dict[str, Any]
    ) -> SafetyCheckResult:
        """Check if a protocol message should be blocked by the safety system.

        Args:
            protocol_type: Type of protocol message
            fuzz_data: Message data to check

        Returns:
            Dictionary with safety check results containing:
            - blocked: True if message should be blocked
            - sanitized: True if message was sanitized
            - blocking_reason: Reason for blocking (if blocked)
            - data: Original or sanitized data
        """
        safety_sanitized = False
        blocking_reason = None
        modified_data = fuzz_data

        if not self.safety_system:
            return {
                "blocked": False,
                "sanitized": False,
                "blocking_reason": None,
                "data": fuzz_data,
            }

        # Check if message should be blocked (duck-typed, guard if present)
        if hasattr(
            self.safety_system, "should_block_protocol_message"
        ) and self.safety_system.should_block_protocol_message(
            protocol_type, fuzz_data
        ):
            blocking_reason = (
                self.safety_system.get_blocking_reason()  # type: ignore[attr-defined]
                if hasattr(self.safety_system, "get_blocking_reason")
                else "blocked_by_safety_system"
            )
            self._logger.warning(
                f"Safety system blocked {protocol_type} message: {blocking_reason}"
            )
            return {
                "blocked": True,
                "sanitized": False,
                "blocking_reason": blocking_reason,
                "data": fuzz_data,
            }

        # Sanitize message if safety system supports it
        original_data = fuzz_data.copy() if isinstance(fuzz_data, dict) else fuzz_data
        if hasattr(self.safety_system, "sanitize_protocol_message"):
            modified_data = self.safety_system.sanitize_protocol_message(
                protocol_type, fuzz_data
            )
            safety_sanitized = modified_data != original_data

        return {
            "blocked": False,
            "sanitized": safety_sanitized,
            "blocking_reason": None,
            "data": modified_data,
        }

    async def _process_single_protocol_fuzz(
        self, protocol_type: str, run_index: int, total_runs: int
    ) -> ProtocolFuzzResult:
        """Process a single protocol fuzzing run.

        Args:
            protocol_type: Type of protocol to fuzz
            run_index: Current run index (0-based)
            total_runs: Total number of runs

        Returns:
            Dictionary with fuzzing results
        """
        try:
            # Use the transport from this client for the fuzzer to send the request
            # Configure the protocol fuzzer to use our transport
            original_transport = self.protocol_fuzzer.transport
            self.protocol_fuzzer.transport = self.transport
            try:
                # Generate only (no send); client handles safety + send
                fuzz_results = await self.protocol_fuzzer.fuzz_protocol_type(
                    protocol_type, 1, generate_only=True
                )
            finally:
                # Restore the original transport configuration
                self.protocol_fuzzer.transport = original_transport

            if not fuzz_results:
                raise ValueError(f"No results returned for {protocol_type}")

            fuzz_result = fuzz_results[0]
            fuzz_data = fuzz_result.get("fuzz_data")

            if fuzz_data is None:
                raise ValueError(f"No fuzz_data returned for {protocol_type}")

            # Log preview of data
            try:
                preview = json.dumps(fuzz_data, indent=2)[:PREVIEW_LENGTH]
            except Exception:
                preview_text = str(fuzz_data) if fuzz_data is not None else "null"
                preview = preview_text[:PREVIEW_LENGTH]
            self._logger.info(
                "Fuzzed %s (run %d/%d) with data: %s...",
                protocol_type,
                run_index + 1,
                total_runs,
                preview,
            )

            # Safety first, then send
            safety_result = await self._check_safety_for_protocol_message(
                protocol_type, fuzz_data
            )
            if safety_result["blocked"]:
                self._logger.warning(
                    "Blocked %s by safety system: %s",
                    protocol_type,
                    safety_result.get("blocking_reason"),
                )
                return {
                    "fuzz_data": fuzz_data,
                    "result": {"response": None, "error": "blocked_by_safety_system"},
                    "safety_blocked": True,
                    "safety_sanitized": False,
                    "success": False,
                }

            data_to_send = safety_result["data"]

            # Route outbound via typed helpers
            try:
                server_response = await self._send_protocol_request(
                    protocol_type, data_to_send
                )
                server_error = None
                success = True
            except Exception as send_exc:
                server_response = None
                server_error = str(send_exc)
                success = False

            # Construct our result
            result = {"response": server_response, "error": server_error}

            # Check for safety metadata
            safety_blocked = safety_result["blocked"]
            safety_sanitized = safety_result["sanitized"]

            return {
                "fuzz_data": fuzz_data,
                "result": result,
                "safety_blocked": safety_blocked,
                "safety_sanitized": safety_sanitized,
                "success": success,
            }

        except Exception as e:
            self._logger.warning(f"Exception during fuzzing {protocol_type}: {e}")
            return {
                "fuzz_data": (fuzz_data if "fuzz_data" in locals() else None),
                "exception": str(e),
                "traceback": traceback.format_exc(),
                "success": False,
            }

    async def fuzz_protocol_type(
        self, protocol_type: str, runs: int = 10
    ) -> List[ProtocolFuzzResult]:
        """Fuzz a specific protocol type."""
        results = []

        for i in range(runs):
            result = await self._process_single_protocol_fuzz(protocol_type, i, runs)
            results.append(result)

        return results

    async def _get_protocol_types(self) -> List[str]:
        """Get list of protocol types to fuzz.

        Returns:
            List of protocol type strings
        """
        try:
            # The protocol fuzzer knows which protocol types to fuzz
            return list(getattr(self.protocol_fuzzer, "PROTOCOL_TYPES", ()))
        except Exception as e:
            self._logger.error(f"Failed to get protocol types: {e}")
            return []

    async def fuzz_all_protocol_types(
        self, runs_per_type: int = 5
    ) -> Dict[str, List[ProtocolFuzzResult]]:
        """Fuzz all protocol types using ProtocolClient safety + sending."""
        try:
            protocol_types = await self._get_protocol_types()
            if not protocol_types:
                self._logger.warning("No protocol types available")
                return {}
            all_results: Dict[str, List[Dict[str, Any]]] = {}
            for pt in protocol_types:
                per_type: List[Dict[str, Any]] = []
                for i in range(runs_per_type):
                    per_type.append(
                        await self._process_single_protocol_fuzz(pt, i, runs_per_type)
                    )
                all_results[pt] = per_type
            return all_results
        except Exception as e:
            self._logger.error(f"Failed to fuzz all protocol types: {e}")
            return {}

    def _extract_params(self, data: Any) -> Dict[str, Any]:
        """Extract parameters from data, safely handling non-dict inputs.

        Args:
            data: Input data that may or may not be a dict

        Returns:
            Dictionary of parameters, or empty dict if not available
        """
        if isinstance(data, dict):
            params = data.get("params", {})
            if isinstance(params, dict):
                return params
        self._logger.debug(
            "Coercing non-dict params to empty dict for %s", type(data).__name__
        )
        return {}

    async def _send_protocol_request(
        self, protocol_type: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send a protocol request based on the type."""
        if protocol_type == "InitializeRequest":
            return await self._send_initialize_request(data)
        elif protocol_type == "ProgressNotification":
            return await self._send_progress_notification(data)
        elif protocol_type == "CancelNotification":
            return await self._send_cancel_notification(data)
        elif protocol_type == "ListResourcesRequest":
            return await self._send_list_resources_request(data)
        elif protocol_type == "ReadResourceRequest":
            return await self._send_read_resource_request(data)
        elif protocol_type == "SetLevelRequest":
            return await self._send_set_level_request(data)
        elif protocol_type == "CreateMessageRequest":
            return await self._send_create_message_request(data)
        elif protocol_type == "ListPromptsRequest":
            return await self._send_list_prompts_request(data)
        elif protocol_type == "GetPromptRequest":
            return await self._send_get_prompt_request(data)
        elif protocol_type == "ListRootsRequest":
            return await self._send_list_roots_request(data)
        elif protocol_type == "SubscribeRequest":
            return await self._send_subscribe_request(data)
        elif protocol_type == "UnsubscribeRequest":
            return await self._send_unsubscribe_request(data)
        elif protocol_type == "CompleteRequest":
            return await self._send_complete_request(data)
        else:
            # Generic JSON-RPC request
            return await self._send_generic_request(data)

    async def _send_initialize_request(self, data: Any) -> Dict[str, Any]:
        """Send an initialize request."""
        return await self.transport.send_request(
            "initialize", self._extract_params(data)
        )

    async def _send_progress_notification(self, data: Any) -> Dict[str, str]:
        """Send a progress notification as JSON-RPC notification (no id)."""
        params = self._extract_params(data)
        await self.transport.send_notification("notifications/progress", params)
        return {"status": "notification_sent"}

    async def _send_cancel_notification(self, data: Any) -> Dict[str, str]:
        """Send a cancel notification as JSON-RPC notification (no id)."""
        params = self._extract_params(data)
        await self.transport.send_notification("notifications/cancelled", params)
        return {"status": "notification_sent"}

    async def _send_list_resources_request(self, data: Any) -> Dict[str, Any]:
        """Send a list resources request."""
        return await self.transport.send_request(
            "resources/list", self._extract_params(data)
        )

    async def _send_read_resource_request(self, data: Any) -> Dict[str, Any]:
        """Send a read resource request."""
        return await self.transport.send_request(
            "resources/read", self._extract_params(data)
        )

    async def _send_set_level_request(self, data: Any) -> Dict[str, Any]:
        """Send a set level request."""
        return await self.transport.send_request(
            "logging/setLevel", self._extract_params(data)
        )

    async def _send_create_message_request(self, data: Any) -> Dict[str, Any]:
        """Send a create message request."""
        return await self.transport.send_request(
            "sampling/createMessage", self._extract_params(data)
        )

    async def _send_list_prompts_request(self, data: Any) -> Dict[str, Any]:
        """Send a list prompts request."""
        return await self.transport.send_request(
            "prompts/list", self._extract_params(data)
        )

    async def _send_get_prompt_request(self, data: Any) -> Dict[str, Any]:
        """Send a get prompt request."""
        return await self.transport.send_request(
            "prompts/get", self._extract_params(data)
        )

    async def _send_list_roots_request(self, data: Any) -> Dict[str, Any]:
        """Send a list roots request."""
        return await self.transport.send_request(
            "roots/list", self._extract_params(data)
        )

    async def _send_subscribe_request(self, data: Any) -> Dict[str, Any]:
        """Send a subscribe request."""
        return await self.transport.send_request(
            "resources/subscribe", self._extract_params(data)
        )

    async def _send_unsubscribe_request(self, data: Any) -> Dict[str, Any]:
        """Send an unsubscribe request."""
        return await self.transport.send_request(
            "resources/unsubscribe", self._extract_params(data)
        )

    async def _send_complete_request(self, data: Any) -> Dict[str, Any]:
        """Send a complete request."""
        return await self.transport.send_request(
            "completion/complete", self._extract_params(data)
        )

    async def _send_generic_request(self, data: Any) -> Dict[str, Any]:
        """Send a generic JSON-RPC request."""
        method = data.get("method") if isinstance(data, dict) else None
        if not isinstance(method, str) or not method:
            method = "unknown"
        params = self._extract_params(data)
        return await self.transport.send_request(method, params)

    async def shutdown(self) -> None:
        """Shutdown the protocol fuzzer."""
        await self.protocol_fuzzer.shutdown()
