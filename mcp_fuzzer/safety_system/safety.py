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

    def __init__(self):
        self.dangerous_url_patterns = [
            r"https?://",  # Any HTTP/HTTPS URL - CRITICAL to block
            r"ftp://",  # FTP URLs
            r"file://",  # File URLs
            r"www\.",  # Common web URLs
            r"[a-zA-Z0-9-]+\.(com|org|net|edu|gov|mil|int|co\.uk|de|fr|jp|cn)",
        ]

        self.dangerous_command_patterns = [
            # Browser/app launching commands
            r"xdg-open",  # Linux open command
            r"open\s+",  # macOS open command
            r"start\s+",  # Windows start command
            r"cmd\s+/c\s+start",  # Windows cmd start
            r"explorer\.exe",  # Windows explorer
            r"rundll32",  # Windows rundll32
            # Browser executables
            r"(firefox|chrome|chromium|safari|edge|opera|brave)\.exe",
            r"(firefox|chrome|chromium|safari|edge|opera|brave)$",
            # System executables that could launch apps
            r"\.exe\s*$",
            r"\.app/Contents/MacOS/",
            r"\.app\s*$",
            r"\.dmg\s*$",
            r"\.msi\s*$",
            # System modification commands
            r"sudo\s+",
            r"rm\s+-rf",
            r"format\s+",
            r"del\s+/[sq]",
            r"shutdown",
            r"reboot",
            r"halt",
        ]

        self.dangerous_argument_names = [
            "url",
            "link",
            "uri",
            "href",
            "website",
            "webpage",
            "browser",
            "application",
            "app",
            "executable",
            "exec",
            "path",
            "file_path",
            "filepath",
            "command",
            "cmd",
        ]

        # Track blocked operations for testing and analysis
        self.blocked_operations = []

    def contains_dangerous_url(self, value: str) -> bool:
        """Check if a string contains a dangerous URL."""
        if not value:
            return False

        for pattern in self.dangerous_url_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False

    def contains_dangerous_command(self, value: str) -> bool:
        """Check if a string contains a dangerous command."""
        if not value:
            return False

        for pattern in self.dangerous_command_patterns:
            if re.search(pattern, value, re.IGNORECASE):
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
        logging.warning(f"SAFETY BLOCK: {tool_name}")
        logging.warning(f"  Reason: {reason}")
        if arguments:
            # Log arguments but truncate long values
            safe_args = {}
            for key, value in arguments.items():
                if isinstance(value, str) and len(value) > 100:
                    safe_args[key] = value[:100] + "..."
                else:
                    safe_args[key] = value
            logging.warning(f"  Arguments: {safe_args}")

        # Add to blocked operations list
        self.blocked_operations.append(
            {"tool_name": tool_name, "reason": reason, "arguments": arguments}
        )


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
