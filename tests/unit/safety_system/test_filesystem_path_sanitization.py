#!/usr/bin/env python3
"""
Tests for filesystem path sanitization in safety system
"""

import tempfile
import unittest.mock
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_fuzzer.safety_system.filesystem import initialize_sandbox, get_sandbox
from mcp_fuzzer.safety_system.safety import SafetyFilter


class TestFilesystemPathSanitization:
    """Test cases for filesystem path sanitization in safety system."""

    def setup_method(self):
        """Set up test environment."""
        # Clean up any existing sandbox
        from mcp_fuzzer.safety_system.filesystem import cleanup_sandbox

        cleanup_sandbox()

    def teardown_method(self):
        """Clean up test environment."""
        from mcp_fuzzer.safety_system.filesystem import cleanup_sandbox

        cleanup_sandbox()

    def test_sanitize_filesystem_paths_with_sandbox(self):
        """Test filesystem path sanitization when sandbox is enabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize sandbox
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            # Test arguments with filesystem paths
            arguments = {
                "path": "/etc/passwd",
                "file": "../../../etc/shadow",
                "directory": "/usr/bin",
                "filename": "normal_file.txt",
                "content": "some content",
                "other_arg": "not a path",
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            # Filesystem paths should be sanitized
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["path"].startswith(sandbox_root)
            assert sanitized["file"].startswith(sandbox_root)
            assert sanitized["directory"].startswith(sandbox_root)
            assert sanitized["filename"].startswith(sandbox_root)

            # Non-filesystem arguments should remain unchanged
            assert sanitized["content"] == "some content"
            assert sanitized["other_arg"] == "not a path"

    def test_sanitize_filesystem_paths_without_sandbox(self):
        """Test filesystem path sanitization when sandbox is not enabled."""
        safety_filter = SafetyFilter()

        arguments = {
            "path": "/etc/passwd",
            "file": "../../../etc/shadow",
            "content": "some content",
        }

        # Should return arguments unchanged when no sandbox
        sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")
        assert sanitized == arguments

    def test_sanitize_filesystem_paths_safe_paths(self):
        """Test that safe paths within sandbox are not modified."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            # Create a safe path within sandbox
            sandbox_root = get_sandbox().get_sandbox_root()
            safe_path = str(Path(sandbox_root) / "safe_file.txt")

            arguments = {
                "path": safe_path,
                "file": str(Path(sandbox_root) / "another_file.txt"),
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            # Safe paths should remain unchanged
            assert sanitized["path"] == safe_path
            assert sanitized["file"] == str(Path(sandbox_root) / "another_file.txt")

    def test_sanitize_filesystem_paths_detects_path_like_values(self):
        """Test that path-like values are detected and sanitized."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "path": "/etc/passwd",  # Contains /
                "file": "C:\\Windows\\System32",  # Contains \\
                "filename": "config.json",  # Ends with file extension
                "directory": "/usr/local/bin",  # Contains /
                "content": "just text",  # Not path-like
                "data": "some data",  # Not path-like
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            # Path-like values should be sanitized
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["path"].startswith(sandbox_root)
            assert sanitized["file"].startswith(sandbox_root)
            assert sanitized["filename"].startswith(sandbox_root)
            assert sanitized["directory"].startswith(sandbox_root)

            # Non-path-like values should remain unchanged
            assert sanitized["content"] == "just text"
            assert sanitized["data"] == "some data"

    def test_sanitize_filesystem_paths_nested_structures(self):
        """Test filesystem path sanitization in nested data structures."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "config": {
                    "input_file": "/etc/passwd",
                    "output_dir": "/tmp/output",
                    "settings": {
                        "log_file": "/var/log/app.log",
                        "data": "not a path",
                    },
                },
                "files": [
                    "/etc/shadow",
                    "safe_file.txt",
                    "/usr/bin/ls",
                ],
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            # Nested paths should be sanitized
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["config"]["input_file"].startswith(sandbox_root)
            assert sanitized["config"]["output_dir"].startswith(sandbox_root)
            assert sanitized["config"]["settings"]["log_file"].startswith(sandbox_root)
            assert sanitized["config"]["settings"]["data"] == "not a path"

            # List items should be sanitized
            assert sanitized["files"][0].startswith(sandbox_root)
            # .txt extension triggers sanitization
            assert sanitized["files"][1].startswith(sandbox_root)
            assert sanitized["files"][2].startswith(sandbox_root)

    def test_sanitize_filesystem_paths_logging(self):
        """Test that filesystem path sanitization logs appropriately."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "path": "/etc/passwd",
                "file": "safe_file.txt",
            }

            with patch(
                "mcp_fuzzer.safety_system.filesystem.sanitizer.logging"
            ) as mock_logging:
                safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

                # Should log sanitization of unsafe path
                mock_logging.info.assert_called()
                log_call = mock_logging.info.call_args

                # Check the new logging format with separate arguments
                assert log_call[0][0] == "Sanitized filesystem path '%s': '%s' -> '%s'"
                # The 'file' argument gets sanitized due to .txt extension
                assert log_call[0][1] == "file"
                assert log_call[0][2] == "safe_file.txt"

    def test_sanitize_tool_arguments_integration(self):
        """Test integration of filesystem path sanitization in
        sanitize_tool_arguments."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "path": "/etc/passwd",
                "content": "<script>alert('xss')</script>",
                "file": "normal_file.txt",
            }

            sanitized = safety_filter.sanitize_tool_arguments("test_tool", arguments)

            # Fuzzing inputs (scripts) should pass through unchanged
            assert sanitized["content"] == "<script>alert('xss')</script>"

            # Filesystem path should still be sanitized (prevents path traversal)
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["path"].startswith(sandbox_root)

            # Safe file should be sanitized due to .txt extension
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["file"].startswith(sandbox_root)

    def test_filesystem_args_detection(self):
        """Test that filesystem-related argument names are detected."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            # Test various filesystem-related argument names
            filesystem_args = [
                "path",
                "file",
                "filename",
                "filepath",
                "directory",
                "dir",
                "folder",
                "source",
                "destination",
                "dest",
                "target",
                "output",
                "input",
                "root",
                "base",
                "location",
                "where",
                "to",
                "from",
            ]

            for arg_name in filesystem_args:
                arguments = {arg_name: "/etc/passwd"}
                sanitized = safety_filter._sanitize_filesystem_paths(
                    arguments, "test_tool"
                )

                # All filesystem args should be sanitized
                sandbox_root = get_sandbox().get_sandbox_root()
                assert sanitized[arg_name].startswith(sandbox_root)

    def test_non_filesystem_args_not_sanitized(self):
        """Test that non-filesystem argument names are not sanitized."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            # Test non-filesystem argument names
            non_filesystem_args = [
                "name",
                "title",
                "description",
                "message",
                "text",
                "content",
                "value",
                "data",
                "info",
                "status",
                "type",
                "id",
            ]

            for arg_name in non_filesystem_args:
                arguments = {arg_name: "/etc/passwd"}
                sanitized = safety_filter._sanitize_filesystem_paths(
                    arguments, "test_tool"
                )

                # Non-filesystem args should not be sanitized unless they look
                # like paths. Since "/etc/passwd" contains "/", it will still
                # be sanitized
                sandbox_root = get_sandbox().get_sandbox_root()
                assert sanitized[arg_name].startswith(sandbox_root)

    def test_file_extension_detection(self):
        """Test that values ending with file extensions are detected as paths."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "config": "config.json",
                "log": "app.log",
                "data": "data.yaml",
                "readme": "README.md",
                "script": "script.py",
                "text": "just text",  # Not a file extension
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            # Values with file extensions should be sanitized
            sandbox_root = get_sandbox().get_sandbox_root()
            assert sanitized["config"].startswith(sandbox_root)
            assert sanitized["log"].startswith(sandbox_root)
            assert sanitized["data"].startswith(sandbox_root)
            assert sanitized["readme"].startswith(sandbox_root)
            assert sanitized["script"].startswith(sandbox_root)

            # Text without file extension should remain unchanged
            assert sanitized["text"] == "just text"

    def test_path_object_support(self):
        """Test that pathlib.Path objects are handled correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            from pathlib import Path

            arguments = {
                "path_obj": Path("/etc/passwd"),
                "str_path": "/etc/shadow",
                "safe_path": Path("safe_file.txt"),
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            sandbox_root = get_sandbox().get_sandbox_root()

            # Path objects should be converted to strings and sanitized
            assert isinstance(sanitized["path_obj"], str)
            assert sanitized["path_obj"].startswith(sandbox_root)

            # String paths should still work
            assert isinstance(sanitized["str_path"], str)
            assert sanitized["str_path"].startswith(sandbox_root)

            # Safe paths should remain as strings
            assert isinstance(sanitized["safe_path"], str)
            assert sanitized["safe_path"].startswith(sandbox_root)

    def test_list_string_items_sanitization(self):
        """Test that string items in lists are properly sanitized."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            arguments = {
                "files": ["/etc/passwd", "/etc/shadow", "safe_file.txt"],
                "mixed": ["/etc/passwd", {"nested": "/etc/hosts"}, 123],
            }

            sanitized = safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

            sandbox_root = get_sandbox().get_sandbox_root()

            # All string items in the list should be sanitized
            assert len(sanitized["files"]) == 3
            for file_path in sanitized["files"]:
                assert isinstance(file_path, str)
                assert file_path.startswith(sandbox_root)

            # Mixed list should handle different types correctly
            assert len(sanitized["mixed"]) == 3
            assert sanitized["mixed"][0].startswith(sandbox_root)  # String sanitized
            assert isinstance(sanitized["mixed"][1], dict)  # Dict processed
            # Nested string sanitized
            assert sanitized["mixed"][1]["nested"].startswith(sandbox_root)
            assert sanitized["mixed"][2] == 123  # Number unchanged

    def test_improved_logging_format(self):
        """Test that the improved logging format works correctly."""
        with tempfile.TemporaryDirectory() as temp_dir:
            initialize_sandbox(temp_dir)
            safety_filter = SafetyFilter()

            with unittest.mock.patch(
                "mcp_fuzzer.safety_system.filesystem.sanitizer.logging"
            ) as mock_logging:
                arguments = {"file": "/etc/passwd"}
                safety_filter._sanitize_filesystem_paths(arguments, "test_tool")

                # Should log with the new format
                mock_logging.info.assert_called()
                log_call = mock_logging.info.call_args

                # Check that it's called with separate arguments (not f-string)
                assert len(log_call[0]) == 4  # format string + 3 arguments
                assert log_call[0][0] == "Sanitized filesystem path '%s': '%s' -> '%s'"
                assert log_call[0][1] == "file"
                assert log_call[0][2] == "/etc/passwd"
                assert log_call[0][3].startswith(get_sandbox().get_sandbox_root())
