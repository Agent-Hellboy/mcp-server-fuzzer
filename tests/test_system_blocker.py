#!/usr/bin/env python3
"""
Unit tests for the system_blocker module.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_fuzzer.system_blocker import (
    SystemCommandBlocker,
    start_system_blocking,
    stop_system_blocking,
    get_blocked_operations,
    clear_blocked_operations,
    is_system_blocking_active,
    get_blocked_commands,
)


class TestSystemCommandBlocker(unittest.TestCase):
    """Test cases for SystemCommandBlocker class."""

    def setUp(self):
        """Set up test fixtures."""
        self.blocker = SystemCommandBlocker()

    def tearDown(self):
        """Clean up after tests."""
        # Ensure blocking is stopped after each test
        try:
            self.blocker.stop_blocking()
        except Exception:
            pass

    def test_init(self):
        """Test SystemCommandBlocker initialization."""
        self.assertIsNone(self.blocker.temp_dir)
        self.assertIsNone(self.blocker.original_path)
        self.assertIsInstance(self.blocker.blocked_commands, list)
        self.assertIn("xdg-open", self.blocker.blocked_commands)
        self.assertIn("firefox", self.blocker.blocked_commands)
        self.assertEqual(len(self.blocker.created_files), 0)

    def test_get_blocked_commands(self):
        """Test getting list of blocked commands."""
        commands = self.blocker.get_blocked_commands()
        self.assertIsInstance(commands, list)
        self.assertIn("xdg-open", commands)
        self.assertIn("firefox", commands)
        self.assertIn("chrome", commands)

        # Ensure it's a copy, not the original
        commands.append("test-command")
        self.assertNotIn("test-command", self.blocker.blocked_commands)

    def test_start_stop_blocking(self):
        """Test starting and stopping command blocking."""
        # Initially not active
        self.assertFalse(self.blocker.is_blocking_active())

        # Start blocking
        self.blocker.start_blocking()
        self.assertTrue(self.blocker.is_blocking_active())
        self.assertIsNotNone(self.blocker.temp_dir)
        self.assertTrue(self.blocker.temp_dir.exists())

        # Check that fake executables were created
        self.assertGreater(len(self.blocker.created_files), 0)
        for fake_exec in self.blocker.created_files:
            self.assertTrue(fake_exec.exists())
            self.assertTrue(os.access(fake_exec, os.X_OK))  # Check executable

        # Stop blocking
        self.blocker.stop_blocking()
        self.assertFalse(self.blocker.is_blocking_active())

    def test_path_modification(self):
        """Test that PATH is modified correctly."""
        original_path = os.environ.get("PATH", "")

        self.blocker.start_blocking()
        try:
            current_path = os.environ.get("PATH", "")
            self.assertTrue(current_path.startswith(str(self.blocker.temp_dir)))
            self.assertIn(original_path, current_path)
        finally:
            self.blocker.stop_blocking()

        # PATH should be restored
        restored_path = os.environ.get("PATH", "")
        self.assertEqual(restored_path, original_path)

    def test_fake_executable_content(self):
        """Test that fake executables have correct content."""
        self.blocker.start_blocking()
        try:
            # Check one of the fake executables
            fake_exec = self.blocker.temp_dir / "xdg-open"
            self.assertTrue(fake_exec.exists())

            content = fake_exec.read_text()
            self.assertIn("#!/usr/bin/env python3", content)
            self.assertIn("FUZZER BLOCKED", content)
            self.assertIn("sys.exit(0)", content)
        finally:
            self.blocker.stop_blocking()

    def test_blocked_operations_logging(self):
        """Test that blocked operations are logged correctly."""
        self.blocker.start_blocking()
        try:
            # Initially no operations
            operations = self.blocker.get_blocked_operations()
            self.assertEqual(len(operations), 0)

            # Simulate running a blocked command
            result = subprocess.run(
                ["xdg-open", "https://example.com"], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("FUZZER BLOCKED", result.stderr)

            # Check that operation was logged
            operations = self.blocker.get_blocked_operations()
            self.assertEqual(len(operations), 1)

            op = operations[0]
            self.assertEqual(op["command"], "xdg-open")
            self.assertEqual(op["args"], "https://example.com")
            self.assertIn("timestamp", op)
            self.assertIn("full_command", op)

        finally:
            self.blocker.stop_blocking()

    def test_clear_blocked_operations(self):
        """Test clearing blocked operations log."""
        self.blocker.start_blocking()
        try:
            # Run a command to create a log entry
            subprocess.run(["firefox", "test.html"], capture_output=True)

            # Verify operation was logged
            operations = self.blocker.get_blocked_operations()
            self.assertEqual(len(operations), 1)

            # Clear operations
            self.blocker.clear_blocked_operations()

            # Verify operations are cleared
            operations = self.blocker.get_blocked_operations()
            self.assertEqual(len(operations), 0)

        finally:
            self.blocker.stop_blocking()

    def test_multiple_commands_blocking(self):
        """Test blocking multiple different commands."""
        self.blocker.start_blocking()
        try:
            # Run multiple commands
            commands_to_test = [
                ["xdg-open", "https://test.com"],
                ["firefox", "page.html"],
                ["chrome", "--new-tab", "https://google.com"],
            ]

            for cmd in commands_to_test:
                result = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn("FUZZER BLOCKED", result.stderr)

            # Check all operations were logged
            operations = self.blocker.get_blocked_operations()
            self.assertEqual(len(operations), len(commands_to_test))

            # Verify each command was logged correctly
            logged_commands = [op["command"] for op in operations]
            self.assertIn("xdg-open", logged_commands)
            self.assertIn("firefox", logged_commands)
            self.assertIn("chrome", logged_commands)

        finally:
            self.blocker.stop_blocking()

    @patch("mcp_fuzzer.system_blocker.logging")
    def test_error_handling(self, mock_logging):
        """Test error handling in various scenarios."""
        # Test stopping when not started
        self.blocker.stop_blocking()  # Should not raise exception

        # Test getting operations when not started
        operations = self.blocker.get_blocked_operations()
        self.assertEqual(len(operations), 0)

        # Test clearing operations when not started
        self.blocker.clear_blocked_operations()  # Should not raise exception


class TestGlobalFunctions(unittest.TestCase):
    """Test cases for global convenience functions."""

    def tearDown(self):
        """Clean up after tests."""
        try:
            stop_system_blocking()
        except Exception:
            pass

    def test_start_stop_system_blocking(self):
        """Test global start/stop functions."""
        # Initially not active
        self.assertFalse(is_system_blocking_active())

        # Start blocking
        start_system_blocking()
        self.assertTrue(is_system_blocking_active())

        # Stop blocking
        stop_system_blocking()
        self.assertFalse(is_system_blocking_active())

    def test_get_blocked_commands_global(self):
        """Test global get_blocked_commands function."""
        commands = get_blocked_commands()
        self.assertIsInstance(commands, list)
        self.assertIn("xdg-open", commands)
        self.assertIn("firefox", commands)

    def test_blocked_operations_global_functions(self):
        """Test global functions for blocked operations."""
        start_system_blocking()
        try:
            # Initially no operations
            operations = get_blocked_operations()
            self.assertEqual(len(operations), 0)

            # Run a command
            subprocess.run(["xdg-open", "test-url"], capture_output=True)

            # Check operation was logged
            operations = get_blocked_operations()
            self.assertEqual(len(operations), 1)
            self.assertEqual(operations[0]["command"], "xdg-open")

            # Clear operations
            clear_blocked_operations()
            operations = get_blocked_operations()
            self.assertEqual(len(operations), 0)

        finally:
            stop_system_blocking()

    def test_integration_with_node_js_simulation(self):
        """Test that blocking works with Node.js-style command execution."""
        start_system_blocking()
        try:
            # Simulate what Node.js child_process.exec would do
            node_commands = [
                ["xdg-open", "https://tally.so/r/mYB6av"],  # feedback tool
                ["firefox", "documentation.html"],  # browser launch
                ["open", "/some/file.pdf"],  # macOS open
            ]

            for cmd in node_commands:
                result = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn("FUZZER BLOCKED", result.stderr)
                self.assertIn("prevent external app launch", result.stderr)

            # Verify all operations were tracked
            operations = get_blocked_operations()
            self.assertEqual(len(operations), len(node_commands))

            # Verify operation types
            commands = [op["command"] for op in operations]
            self.assertIn("xdg-open", commands)
            self.assertIn("firefox", commands)
            self.assertIn("open", commands)

        finally:
            stop_system_blocking()


class TestSystemBlockerEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_multiple_start_calls(self):
        """Test calling start_blocking multiple times."""
        blocker = SystemCommandBlocker()

        try:
            # First start should work
            blocker.start_blocking()
            self.assertTrue(blocker.is_blocking_active())

            # Second start should handle gracefully
            blocker.start_blocking()
            self.assertTrue(blocker.is_blocking_active())

        finally:
            blocker.stop_blocking()

    def test_stop_without_start(self):
        """Test stopping blocking without starting."""
        blocker = SystemCommandBlocker()

        # Should not raise exception
        blocker.stop_blocking()
        self.assertFalse(blocker.is_blocking_active())

    def test_command_with_no_args(self):
        """Test blocking commands with no arguments."""
        start_system_blocking()
        try:
            result = subprocess.run(["firefox"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertIn("FUZZER BLOCKED", result.stderr)

            operations = get_blocked_operations()
            self.assertEqual(len(operations), 1)
            self.assertEqual(operations[0]["command"], "firefox")
            self.assertEqual(operations[0]["args"], "")

        finally:
            stop_system_blocking()

    def test_command_with_special_characters(self):
        """Test blocking commands with special characters in arguments."""
        start_system_blocking()
        try:
            special_url = "https://example.com/path?param=value&other=test#anchor"
            result = subprocess.run(
                ["xdg-open", special_url], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("FUZZER BLOCKED", result.stderr)

            operations = get_blocked_operations()
            self.assertEqual(len(operations), 1)
            self.assertEqual(operations[0]["args"], special_url)

        finally:
            stop_system_blocking()


if __name__ == "__main__":
    unittest.main()
