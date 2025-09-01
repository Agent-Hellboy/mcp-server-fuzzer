#!/usr/bin/env python3
"""
Protocol Client Module

This module provides functionality for fuzzing MCP protocol types.
"""

import json
import logging
import traceback
from typing import Any, Dict, List, Optional

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
    ) -> Dict[str, Any]:
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
    ) -> Dict[str, Any]:
        """Process a single protocol fuzzing run.

        Args:
            protocol_type: Type of protocol to fuzz
            run_index: Current run index (0-based)
            total_runs: Total number of runs

        Returns:
            Dictionary with fuzzing results
        """
        try:
            # Generate fuzz data using the fuzzer
            fuzz_results = await self.protocol_fuzzer.fuzz_protocol_type(
                protocol_type, 1
            )
            if not fuzz_results or "fuzz_data" not in fuzz_results[0]:
                raise ValueError(f"No fuzz_data returned for {protocol_type}")
            fuzz_data = fuzz_results[0]["fuzz_data"]

            # Check safety
            safety_result = await self._check_safety_for_protocol_message(
                protocol_type, fuzz_data
            )

            # If blocked by safety system, return early
            if safety_result["blocked"]:
                return {
                    "fuzz_data": fuzz_data,
                    "safety_blocked": True,
                    "blocking_reason": safety_result["blocking_reason"],
                    "success": False,
                }

            # Use potentially sanitized data
            fuzz_data = safety_result["data"]
            safety_sanitized = safety_result["sanitized"]

            # Log preview of data
            try:
                preview = json.dumps(fuzz_data, indent=2)[:200]
            except Exception:
                preview = (str(fuzz_data) if fuzz_data is not None else "null")[:200]
            self._logger.info(
                "Fuzzing %s (run %d/%d) with data: %s...",
                protocol_type,
                run_index + 1,
                total_runs,
                preview,
            )

            # Send the fuzz data through transport
            result = await self._send_protocol_request(protocol_type, fuzz_data)

            # Check for safety metadata in response
            safety_blocked = safety_result["blocked"]
            if "_meta" in result and isinstance(result["_meta"], dict):
                if "safety_blocked" in result["_meta"]:
                    safety_blocked = result["_meta"]["safety_blocked"]
                if "safety_sanitized" in result["_meta"]:
                    safety_sanitized = result["_meta"]["safety_sanitized"]

            return {
                "fuzz_data": fuzz_data,
                "result": result,
                "safety_blocked": safety_blocked,
                "safety_sanitized": safety_sanitized,
                "success": True,
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
    ) -> List[Dict[str, Any]]:
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
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fuzz all protocol types using the ProtocolFuzzer and group results."""
        try:
            # The protocol fuzzer now actually sends requests to the server
            results = await self.protocol_fuzzer.fuzz_all_protocol_types(runs_per_type)
            if not results:
                self._logger.warning("No protocol types returned from fuzzer")
            return results
        except Exception as e:
            self._logger.error(f"Failed to fuzz all protocol types: {e}")
            return {}

    async def _send_protocol_request(
        self, protocol_type: str, data: Dict[str, Any]
    ) -> Any:
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

    async def _send_initialize_request(self, data: Dict[str, Any]) -> Any:
        """Send an initialize request."""
        return await self.transport.send_request("initialize", data.get("params", {}))

    async def _send_progress_notification(self, data: Dict[str, Any]) -> Any:
        """Send a progress notification as JSON-RPC notification (no id)."""
        params = data.get("params", {})
        if not isinstance(params, dict):
            self._logger.debug(
                "Non-dict params for progress notification; coercing to empty dict"
            )
            params = {}
        await self.transport.send_notification("notifications/progress", params)
        return {"status": "notification_sent"}

    async def _send_cancel_notification(self, data: Dict[str, Any]) -> Any:
        """Send a cancel notification as JSON-RPC notification (no id)."""
        params = data.get("params", {})
        if not isinstance(params, dict):
            self._logger.debug(
                "Non-dict params for cancel notification; coercing to empty dict"
            )
            params = {}
        await self.transport.send_notification("notifications/cancelled", params)
        return {"status": "notification_sent"}

    async def _send_list_resources_request(self, data: Dict[str, Any]) -> Any:
        """Send a list resources request."""
        return await self.transport.send_request(
            "resources/list", data.get("params", {})
        )

    async def _send_read_resource_request(self, data: Dict[str, Any]) -> Any:
        """Send a read resource request."""
        return await self.transport.send_request(
            "resources/read", data.get("params", {})
        )

    async def _send_set_level_request(self, data: Dict[str, Any]) -> Any:
        """Send a set level request."""
        return await self.transport.send_request(
            "logging/setLevel", data.get("params", {})
        )

    async def _send_create_message_request(self, data: Dict[str, Any]) -> Any:
        """Send a create message request."""
        return await self.transport.send_request(
            "sampling/createMessage", data.get("params", {})
        )

    async def _send_list_prompts_request(self, data: Dict[str, Any]) -> Any:
        """Send a list prompts request."""
        return await self.transport.send_request("prompts/list", data.get("params", {}))

    async def _send_get_prompt_request(self, data: Dict[str, Any]) -> Any:
        """Send a get prompt request."""
        return await self.transport.send_request("prompts/get", data.get("params", {}))

    async def _send_list_roots_request(self, data: Dict[str, Any]) -> Any:
        """Send a list roots request."""
        return await self.transport.send_request("roots/list", data.get("params", {}))

    async def _send_subscribe_request(self, data: Dict[str, Any]) -> Any:
        """Send a subscribe request."""
        return await self.transport.send_request(
            "resources/subscribe", data.get("params", {})
        )

    async def _send_unsubscribe_request(self, data: Dict[str, Any]) -> Any:
        """Send an unsubscribe request."""
        return await self.transport.send_request(
            "resources/unsubscribe", data.get("params", {})
        )

    async def _send_complete_request(self, data: Dict[str, Any]) -> Any:
        """Send a complete request."""
        return await self.transport.send_request(
            "completion/complete", data.get("params", {})
        )

    async def _send_generic_request(self, data: Dict[str, Any]) -> Any:
        """Send a generic JSON-RPC request."""
        method = data.get("method", "unknown")
        params = data.get("params", {})
        return await self.transport.send_request(method, params)

    async def shutdown(self):
        """Shutdown the protocol fuzzer."""
        await self.protocol_fuzzer.shutdown()
