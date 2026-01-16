#!/usr/bin/env python3
"""
Safety Module for MCP Fuzzer

- Default implementation: argument-based safety filtering.
- Pluggable: you can replace the active safety provider at runtime or via CLI.

System-level blocking (preventing actual browser/app launches)
is handled by the system_blocker module.
"""

import logging
from copy import deepcopy
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import emoji

from .filesystem import (
    PathSanitizer,
    initialize_sandbox as fs_initialize_sandbox,
    get_sandbox as fs_get_sandbox,
)
from .detection import (
    DEFAULT_DANGEROUS_URL_PATTERNS,
    DEFAULT_DANGEROUS_SCRIPT_PATTERNS,
    DEFAULT_DANGEROUS_COMMAND_PATTERNS,
    DEFAULT_DANGEROUS_ARGUMENT_NAMES,
    DangerDetector,
    DangerType,
)
from .reporting import SafetyEventLogger


@runtime_checkable
class SafetyProvider(Protocol):
    """Protocol for pluggable safety providers."""

    def set_fs_root(self, root: str | Path) -> None: ...
    def sanitize_tool_arguments(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]: ...
    def should_skip_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> bool: ...
    def create_safe_mock_response(self, tool_name: str) -> dict[str, Any]: ...
    def log_blocked_operation(
        self, tool_name: str, arguments: dict[str, Any], reason: str
    ) -> None: ...


@runtime_checkable
class SandboxProvider(Protocol):
    """Protocol for pluggable sandbox providers."""

    def initialize(self, root: str | Path) -> None: ...
    def get_sandbox(self) -> Any | None: ...


class DefaultSandboxProvider(SandboxProvider):
    """Default implementation using existing filesystem sandbox."""

    def initialize(self, root: str | Path) -> None:
        fs_initialize_sandbox(str(root))

    def get_sandbox(self) -> Any | None:
        return fs_get_sandbox()


class SafetyFilter(SafetyProvider):
    """Filters and suppresses dangerous operations during fuzzing."""

    def __init__(
        self,
        dangerous_url_patterns: list[str] | None = None,
        dangerous_script_patterns: list[str] | None = None,
        dangerous_command_patterns: list[str] | None = None,
        dangerous_argument_names: list[str] | None = None,
        sandbox_provider: SandboxProvider | None = None,
    ):
        # Allow dependency injection of patterns for easier testing and configurability
        self.detector = DangerDetector(
            dangerous_url_patterns or DEFAULT_DANGEROUS_URL_PATTERNS,
            dangerous_script_patterns or DEFAULT_DANGEROUS_SCRIPT_PATTERNS,
            dangerous_command_patterns or DEFAULT_DANGEROUS_COMMAND_PATTERNS,
        )
        # Backwards-compatible attributes used by unit tests/documentation
        self.dangerous_url_patterns = list(self.detector.url_patterns)
        self.dangerous_script_patterns = list(self.detector.script_patterns)
        self.dangerous_command_patterns = list(self.detector.command_patterns)
        # Normalize argument names for case-insensitive membership checks
        self.dangerous_argument_names = {
            n.lower()
            for n in (dangerous_argument_names or DEFAULT_DANGEROUS_ARGUMENT_NAMES)
        }

        # Track blocked operations for testing and analysis
        self.blocked_operations: list[dict[str, Any]] = []
        self._fs_root: Path | None = None
        self.sandbox_provider = sandbox_provider or DefaultSandboxProvider()
        self._event_logger = SafetyEventLogger(self.detector)

    def set_fs_root(self, root: str | Path) -> None:
        """Initialize filesystem sandbox with the specified root directory."""
        try:
            self.sandbox_provider.initialize(str(root))
            logging.info("Filesystem sandbox initialized at: %s", root)
        except Exception as e:
            logging.error(
                f"Failed to initialize filesystem sandbox with root '{root}': {e}"
            )
            # Initialize with default sandbox
            self.sandbox_provider.initialize(".")

    def contains_dangerous_url(self, value: str) -> bool:
        """
        Check if a string contains a dangerous URL pattern.

        Detects HTTP/HTTPS URLs, FTP, file:// protocols, and common web domains.

        Args:
            value: String to check for dangerous URLs

        Returns:
            True if dangerous URL pattern found, False otherwise
        """
        return self.detector.contains(value, DangerType.URL)

    def contains_dangerous_script(self, value: str) -> bool:
        """
        Check if a string contains dangerous script injection patterns.

        Detects HTML/JavaScript injection like <script>, event handlers, eval(), etc.

        Args:
            value: String to check for script injection patterns

        Returns:
            True if dangerous script pattern found, False otherwise
        """
        return self.detector.contains(value, DangerType.SCRIPT)

    def contains_dangerous_command(self, value: str) -> bool:
        """
        Check if a string contains dangerous command patterns.

        Detects browser/app launches (xdg-open, start, open), system modification
        commands (sudo, rm -rf, format, shutdown), and executable patterns.

        Args:
            value: String to check for dangerous commands

        Returns:
            True if dangerous command pattern found, False otherwise
        """
        return self.detector.contains(value, DangerType.COMMAND)

    def sanitize_tool_arguments(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Sanitize tool arguments to enforce filesystem sandbox.

        Note: URLs, scripts, and commands in arguments are NOT sanitized - these
        are fuzzing inputs meant to test the server. The safety system protects
        against actual dangerous operations at the system level (command execution,
        filesystem access, network access), not test data in arguments.
        """
        if not arguments:
            return arguments

        # Pass through arguments as-is (no URL/script/command sanitization)
        sanitized_args = arguments

        # Sanitize filesystem paths if sandbox is enabled (prevents path traversal)
        sandbox = self.sandbox_provider.get_sandbox()
        if sandbox:
            sanitized_args = self._sanitize_filesystem_paths(sanitized_args, tool_name)

        return sanitized_args

    def _sanitize_filesystem_paths(
        self, arguments: dict[str, Any], tool_name: str
    ) -> dict[str, Any]:
        """Sanitize filesystem paths to ensure they're within the sandbox."""
        sandbox = self.sandbox_provider.get_sandbox()
        if not sandbox:
            return arguments

        sanitizer = PathSanitizer(sandbox)
        return sanitizer.sanitize_arguments(arguments, tool_name)

    def _sanitize_value(self, key: str, value: Any) -> Any:
        """
        Recursively sanitize any value (string, dict, list, etc.).

        Handles nested structures by recursively applying sanitization rules.
        Strings are checked for dangerous patterns; dicts and lists are traversed.

        Args:
            key: Argument name/path (used for logging context)
            value: Value to sanitize (any type)

        Returns:
            Sanitized value with dangerous patterns replaced or removed
        """
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
        """
        Sanitize a string argument.

        For fuzzing purposes, we do NOT sanitize URLs, scripts, or commands in
        arguments - these are test inputs meant to find vulnerabilities in the server.
        The actual protection comes from:
        - Command blocker (prevents actual command execution)
        - Filesystem sandbox (prevents path traversal)
        - Network policy (prevents unauthorized network access)

        Filesystem path sanitization is handled separately by
        _sanitize_filesystem_paths.
        """
        # Don't sanitize URLs, scripts, or commands - allow them to pass through
        # as fuzzing inputs. The safety system protects against actual dangerous
        # operations at the system level, not test data in arguments.
        return value

    def should_skip_tool_call(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """
        Determine if a tool call should be completely skipped based on
        dangerous content in arguments.

        For fuzzing purposes, we do NOT block tool calls based on URLs or scripts
        in arguments - these are test inputs meant to find vulnerabilities in the
        server. The safety system protects against actual dangerous operations:
        - Command execution (handled by command blocker)
        - Filesystem path traversal (handled by filesystem sandbox)
        - Network access (handled by network policy)

        This method should only block if there's a clear indication that the tool
        itself would execute a dangerous operation, not just because the arguments
        contain test data.
        """
        # Don't block fuzzing inputs - allow them to be sent to the server
        # The actual protection comes from:
        # 1. Command blocker (prevents actual command execution)
        # 2. Filesystem sandbox (prevents path traversal)
        # 3. Network policy (prevents unauthorized network access)
        return False

    def create_safe_mock_response(self, tool_name: str) -> dict[str, Any]:
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
        self, tool_name: str, arguments: dict[str, Any], reason: str
    ):
        """Log details about blocked operations for analysis."""
        # Enhanced logging with more structure
        # Log tool first so tests can assert on the first call containing the tool name
        event = self._event_logger.build_blocked_operation(tool_name, arguments, reason)
        logging.warning("Tool: %s", tool_name)
        logging.warning("Reason: %s", reason)
        logging.warning("Timestamp: %s", event.timestamp)
        logging.warning("=" * 80)
        logging.warning("\U0001f6ab SAFETY BLOCK DETECTED")
        logging.warning("=" * 80)

        if event.arguments:
            logging.warning("Blocked Arguments:")
            logging.warning("Arguments: %s", event.arguments)

            if event.dangerous_content:
                logging.warning(
                    "%s DANGEROUS CONTENT DETECTED:",
                    emoji.emojize(":police_car_light:"),
                )
                for content in event.dangerous_content:
                    logging.warning(
                        "  • %s in '%s': %s",
                        content.match.danger_type.value.upper(),
                        content.key,
                        content.match.preview,
                    )

        logging.warning("=" * 80)

        # Add to blocked operations list for summary reporting
        stored_arguments = deepcopy(arguments) if arguments is not None else None

        self.blocked_operations.append(
            {
                "timestamp": event.timestamp,
                "tool_name": tool_name,
                "reason": reason,
                "arguments": stored_arguments,
                "dangerous_content": [
                    f"{entry.match.danger_type.value.upper()} in '{entry.key}': "
                    f"{entry.match.preview}"
                    for entry in event.dangerous_content
                ],
            }
        )

    def get_blocked_operations_summary(self) -> dict[str, Any]:
        """
        Get a summary of all blocked operations for reporting.

        Returns:
            Dictionary with keys:
            - total_blocked: Total number of blocked operations
            - tools_blocked: Dict mapping tool names to block counts
            - reasons: Dict mapping block reasons to counts
            - dangerous_content_types: Dict of content counts (URLs, commands, etc.)
        """
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

    def _iter_string_values(self, key: str, value: Any):
        """Yield (key_path, string_value) pairs from nested arguments."""
        if isinstance(value, str):
            yield key, value
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                yield from self._iter_string_values(f"{key}[{idx}]", item)
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                nested_key = f"{key}.{sub_key}" if key else sub_key
                yield from self._iter_string_values(nested_key, sub_value)

    @staticmethod
    def _preview_value(value: str, limit: int = 50) -> str:
        """Return a short preview string for logging."""
        if len(value) <= limit:
            return value
        return f"{value[:limit]}..."
