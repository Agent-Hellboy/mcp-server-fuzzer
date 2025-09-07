#!/usr/bin/env python3
"""
Safety Module for MCP Fuzzer

- Default implementation: argument-based safety filtering.
- Pluggable: you can replace the active safety provider at runtime or via CLI.

System-level blocking (preventing actual browser/app launches)
is handled by the system_blocker module.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, Protocol, runtime_checkable

import emoji

from .patterns import (
    DEFAULT_DANGEROUS_URL_PATTERNS,
    DEFAULT_DANGEROUS_COMMAND_PATTERNS,
    DEFAULT_DANGEROUS_ARGUMENT_NAMES,
)


@runtime_checkable
class SafetyProvider(Protocol):
    """Protocol for pluggable safety providers."""

    def set_fs_root(self, root: str | Path) -> None: ...
    def sanitize_tool_arguments(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]: ...
    def should_skip_tool_call(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> bool: ...
    def create_safe_mock_response(self, tool_name: str) -> Dict[str, Any]: ...
    def log_blocked_operation(
        self, tool_name: str, arguments: Dict[str, Any], reason: str
    ) -> None: ...


class SafetyFilter(SafetyProvider):
    """Filters and suppresses dangerous operations during fuzzing."""

    def __init__(
        self,
        dangerous_url_patterns: list[str] | None = None,
        dangerous_command_patterns: list[str] | None = None,
        dangerous_argument_names: list[str] | None = None,
    ):
        # Allow dependency injection of patterns for easier testing and configurability
        self.dangerous_url_patterns = self._compile_patterns(
            dangerous_url_patterns or DEFAULT_DANGEROUS_URL_PATTERNS
        )
        self.dangerous_command_patterns = self._compile_patterns(
            dangerous_command_patterns or DEFAULT_DANGEROUS_COMMAND_PATTERNS
        )
        # Normalize argument names for case-insensitive membership checks
        self.dangerous_argument_names = {
            n.lower()
            for n in (dangerous_argument_names or DEFAULT_DANGEROUS_ARGUMENT_NAMES)
        }

        # Track blocked operations for testing and analysis
        self.blocked_operations = []
        self._fs_root: Path | None = None

    def set_fs_root(self, root: str | Path) -> None:
        """Record a sandbox root for potential future path validations."""
        try:
            self._fs_root = Path(root)
        except Exception:
            self._fs_root = None

    def _compile_patterns(self, patterns):
        """Compile string patterns into regex Pattern objects."""
        compiled = []
        for p in patterns:
            if isinstance(p, re.Pattern):
                compiled.append(p)
            else:
                compiled.append(re.compile(p, re.IGNORECASE))
        return compiled

    def contains_dangerous_url(self, value: str) -> bool:
        """Check if a string contains a dangerous URL."""
        if not value:
            return False

        for pattern in self.dangerous_url_patterns:
            if pattern.search(value):
                return True
        return False

    def contains_dangerous_command(self, value: str) -> bool:
        """Check if a string contains a dangerous command."""
        if not value:
            return False

        for pattern in self.dangerous_command_patterns:
            if pattern.search(value):
                return True
        return False

    def sanitize_tool_arguments(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Sanitize tool arguments to remove dangerous content recursively."""
        if not arguments:
            return arguments

        return self._sanitize_value("root", arguments)

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """Recursively sanitize any value (string, dict, list, etc.)."""
        if isinstance(value, str):
            return self._sanitize_string_argument(key, value)
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            sanitized_dict = {}
            for sub_key, sub_value in value.items():
                sanitized_dict[sub_key] = self._sanitize_value(sub_key, sub_value)
            return sanitized_dict
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [
                self._sanitize_value(f"{key}[{i}]", item)
                for i, item in enumerate(value)
            ]
        else:
            # Return other types as-is (int, bool, None, etc.)
            return value

    def _sanitize_string_argument(self, arg_name: str, value: str) -> str:
        """Sanitize a string argument."""
        if not value:
            return value

        # CRITICAL: Check for URLs - completely block them
        if self.contains_dangerous_url(value):
            logging.warning(f"BLOCKED dangerous URL in {arg_name}: {value[:50]}...")
            return "[BLOCKED_URL]"

        # CRITICAL: Check for dangerous commands - completely block them
        if self.contains_dangerous_command(value):
            logging.warning(f"BLOCKED dangerous command in {arg_name}: {value[:50]}...")
            return "[BLOCKED_COMMAND]"

        # Extra scrutiny for dangerous argument names
        if arg_name.lower() in self.dangerous_argument_names:
            # Be extra cautious with these argument names
            if any(
                danger in value.lower()
                for danger in [
                    "http",
                    "www",
                    "browser",
                    "open",
                    "launch",
                    "start",
                    ".exe",
                    ".app",
                ]
            ):
                logging.warning(
                    f"BLOCKED potentially dangerous {arg_name}: {value[:50]}..."
                )
                return "[BLOCKED_SUSPICIOUS]"

        return value

    def should_skip_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> bool:
        """
        Determine if a tool call should be completely skipped based on
        dangerous content in arguments.
        """

        # If no arguments, allow the tool to run (we'll handle dangerous
        # operations at execution level)
        if not arguments:
            return False

        # Check ALL arguments for dangerous content
        for key, value in arguments.items():
            if isinstance(value, str):
                # BLOCK dangerous URLs (specific dangerous ones)
                if self.contains_dangerous_url(value):
                    logging.warning(
                        f"BLOCKING tool call - dangerous URL in {key}: {value[:50]}..."
                    )
                    return True

                # BLOCK any dangerous commands
                if self.contains_dangerous_command(value):
                    logging.warning(
                        f"BLOCKING tool call - dangerous command in {key}: "
                        f"{value[:50]}..."
                    )
                    return True

            elif isinstance(value, list):
                # Check list items
                for item in value:
                    if isinstance(item, str):
                        if self.contains_dangerous_url(
                            item
                        ) or self.contains_dangerous_command(item):
                            logging.warning(
                                f"BLOCKING tool call - dangerous content in {key}: "
                                f"{item[:50]}..."
                            )
                            return True

        return False

    def create_safe_mock_response(self, tool_name: str) -> Dict[str, Any]:
        """Create a safe mock response for blocked tool calls."""
        return {
            "error": {
                "code": -32603,
                "message": f"[SAFETY BLOCKED] Operation blocked to prevent opening "
                f"browsers/external applications during fuzzing. Tool: {tool_name}",
            },
            "_meta": {
                "safety_blocked": True,
                "tool_name": tool_name,
                "reason": "Blocked URL/external app operation",
            },
        }

    def log_blocked_operation(
        self, tool_name: str, arguments: Dict[str, Any], reason: str
    ):
        """Log details about blocked operations for analysis."""
        # Enhanced logging with more structure
        # Log tool first so tests can assert on the first call containing the tool name
        logging.warning(f"Tool: {tool_name}")
        logging.warning(f"Reason: {reason}")
        logging.warning(f"Timestamp: {self._get_timestamp()}")
        logging.warning("=" * 80)
        logging.warning("\U0001f6ab SAFETY BLOCK DETECTED")
        logging.warning("=" * 80)

        if arguments:
            logging.warning("Blocked Arguments:")
            # Log arguments but truncate long values and highlight dangerous content
            safe_args = {}
            dangerous_content = []

            for key, value in arguments.items():
                if isinstance(value, str):
                    if len(value) > 100:
                        safe_args[key] = value[:100] + "..."
                    else:
                        safe_args[key] = value

                    # Check for dangerous content in this value
                    if self.contains_dangerous_url(value):
                        dangerous_content.append(f"URL in '{key}': {value[:50]}...")
                    elif self.contains_dangerous_command(value):
                        dangerous_content.append(f"Command in '{key}': {value[:50]}...")

                elif isinstance(value, list):
                    # Check list items for dangerous content
                    if len(value) > 10:
                        safe_args[key] = f"[{len(value)} items] - {str(value[:3])}..."
                    else:
                        safe_args[key] = value

                    # Check for dangerous content in list items
                    for item in value[:5]:  # Check first 5 items
                        if isinstance(item, str):
                            if self.contains_dangerous_url(item):
                                dangerous_content.append(
                                    f"URL in '{key}' list: {item[:50]}..."
                                )
                            elif self.contains_dangerous_command(item):
                                dangerous_content.append(
                                    f"Command in '{key}' list: {item[:50]}..."
                                )
                else:
                    safe_args[key] = value

            logging.warning(f"Arguments: {safe_args}")

            if dangerous_content:
                logging.warning(
                    f"{emoji.emojize(':police_car_light:')} DANGEROUS CONTENT DETECTED:"
                )
                for content in dangerous_content:
                    logging.warning(f"  • {content}")

        logging.warning("=" * 80)

        # Add to blocked operations list for summary reporting
        self.blocked_operations.append(
            {
                "timestamp": self._get_timestamp(),
                "tool_name": tool_name,
                "reason": reason,
                "arguments": arguments,
                "dangerous_content": (
                    dangerous_content if "dangerous_content" in locals() else []
                ),
            }
        )

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime

        return datetime.now().isoformat()

    def get_blocked_operations_summary(self) -> Dict[str, Any]:
        """Get a summary of all blocked operations for reporting."""
        if not self.blocked_operations:
            return {"total_blocked": 0, "tools_blocked": {}, "reasons": {}}

        summary = {
            "total_blocked": len(self.blocked_operations),
            "tools_blocked": {},
            "reasons": {},
            "dangerous_content_types": {},
        }

        for op in self.blocked_operations:
            # Count by tool
            tool = op["tool_name"]
            if tool not in summary["tools_blocked"]:
                summary["tools_blocked"][tool] = 0
            summary["tools_blocked"][tool] += 1

            # Count by reason
            reason = op["reason"]
            if reason not in summary["reasons"]:
                summary["reasons"][reason] = 0
            summary["reasons"][reason] += 1

            # Count dangerous content types
            if "dangerous_content" in op and op["dangerous_content"]:
                for content in op["dangerous_content"]:
                    if "URL" in content:
                        summary["dangerous_content_types"]["urls"] = (
                            summary["dangerous_content_types"].get("urls", 0) + 1
                        )
                    elif "Command" in content:
                        summary["dangerous_content_types"]["commands"] = (
                            summary["dangerous_content_types"].get("commands", 0) + 1
                        )

        return summary


_current_safety: SafetyProvider = SafetyFilter()


def set_safety_provider(provider: SafetyProvider) -> None:
    """Replace the active safety provider at runtime."""
    global _current_safety
    if not isinstance(provider, SafetyProvider):
        raise TypeError("provider must implement SafetyProvider protocol")
    _current_safety = provider


def load_safety_plugin(dotted_path: str) -> None:
    """
    Load a safety provider from a module path.
    The module may expose either `get_safety()` -> SafetyProvider or `safety` object.
    """
    import importlib

    module = importlib.import_module(dotted_path)
    provider: SafetyProvider | None = None
    if hasattr(module, "get_safety"):
        provider = getattr(module, "get_safety")()
    elif hasattr(module, "safety"):
        provider = getattr(module, "safety")
    if provider is None:
        raise ImportError(
            f"Safety plugin '{dotted_path}' did not expose get_safety() or safety"
        )
    set_safety_provider(provider)


def disable_safety() -> None:
    """Disable safety by installing a no-op provider."""

    class _NoopSafety(SafetyProvider):
        def set_fs_root(self, root: str | Path) -> None:  # noqa: ARG002
            return

        def sanitize_tool_arguments(
            self, tool_name: str, arguments: Dict[str, Any]
        ) -> Dict[str, Any]:  # noqa: ARG002
            return arguments

        def should_skip_tool_call(
            self, tool_name: str, arguments: Dict[str, Any]
        ) -> bool:  # noqa: ARG002
            return False

        def create_safe_mock_response(self, tool_name: str) -> Dict[str, Any]:  # noqa: ARG002
            return {"result": {"content": [{"text": "[SAFETY DISABLED]"}]}}

        def log_blocked_operation(
            self, tool_name: str, arguments: Dict[str, Any], reason: str
        ) -> None:  # noqa: ARG002
            logging.warning("SAFETY DISABLED: %s", reason)

    set_safety_provider(_NoopSafety())


# Backwards-compatible helpers
def is_safe_tool_call(tool_name: str, arguments: Dict[str, Any]) -> bool:
    return not _current_safety.should_skip_tool_call(tool_name, arguments)


def sanitize_tool_call(
    tool_name: str, arguments: Dict[str, Any]
) -> tuple[str, Dict[str, Any]]:
    sanitized_args = _current_safety.sanitize_tool_arguments(tool_name, arguments)
    return tool_name, sanitized_args


def create_safety_response(tool_name: str) -> Dict[str, Any]:
    return _current_safety.create_safe_mock_response(tool_name)


# Expose a name for direct use where needed
safety_filter: SafetyProvider = _current_safety
