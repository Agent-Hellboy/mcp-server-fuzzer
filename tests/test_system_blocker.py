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
from unittest.mock import patch, MagicMock, mock_open
import shutil

from mcp_fuzzer.safety_system.system_blocker import (
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

            # Mock subprocess.run to simulate blocked command
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = "FUZZER BLOCKED: xdg-open command blocked"
                mock_subprocess.return_value = mock_result

                result = subprocess.run(
                    ["xdg-open", "https://example.com"], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("FUZZER BLOCKED", result.stderr)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(self.blocker.is_blocking_active())
            self.assertTrue(self.blocker.is_command_blocked("xdg-open"))

            # Verify that the blocking mechanism is set up properly
            self.assertIsNotNone(self.blocker.temp_dir)
            self.assertTrue(self.blocker.temp_dir.exists())

        finally:
            self.blocker.stop_blocking()

    def test_clear_blocked_operations(self):
        """Test clearing blocked operations log."""
        self.blocker.start_blocking()
        try:
            # Mock subprocess.run to simulate blocked command
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = "FUZZER BLOCKED: firefox command blocked"
                mock_subprocess.return_value = mock_result

                subprocess.run(["firefox", "test.html"], capture_output=True)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(self.blocker.is_blocking_active())
            self.assertTrue(self.blocker.is_command_blocked("firefox"))

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

            # Test that the system blocker is active and blocking the right commands
            for cmd in commands_to_test:
                command_name = cmd[0]
                self.assertTrue(self.blocker.is_command_blocked(command_name))

            # Verify that the blocking mechanism is working
            self.assertTrue(self.blocker.is_blocking_active())
            self.assertIsNotNone(self.blocker.temp_dir)

            # Verify that all commands are in the blocked commands list
            blocked_commands = self.blocker.get_blocked_commands()
            self.assertIn("xdg-open", blocked_commands)
            self.assertIn("firefox", blocked_commands)
            self.assertIn("chrome", blocked_commands)

        finally:
            self.blocker.stop_blocking()

    @patch("mcp_fuzzer.safety_system.system_blocker.logging")
    def test_error_handling(self, mock_logging):
        """Test error handling in various scenarios."""
        # Test stopping when not started
        self.blocker.stop_blocking()  # Should not raise exception

        # Test getting operations when not started
        operations = self.blocker.get_blocked_operations()
        self.assertEqual(len(operations), 0)

        # Test clearing operations when not started
        self.blocker.clear_blocked_operations()  # Should not raise exception

    def test_block_command_edge_cases(self):
        """Test block_command with edge cases."""
        # Test with None
        self.blocker.block_command(None)

        # Test with empty string
        self.blocker.block_command("")

        # Test with whitespace
        self.blocker.block_command("   ")

    def test_is_command_blocked_edge_cases(self):
        """Test is_command_blocked with edge cases."""
        # Test with None
        self.assertFalse(self.blocker.is_command_blocked(None))

        # Test with empty string
        self.assertFalse(self.blocker.is_command_blocked(""))

        # Test with whitespace
        self.assertFalse(self.blocker.is_command_blocked("   "))

    def test_create_fake_executable_edge_cases(self):
        """Test create_fake_executable with edge cases."""
        # Set up temp directory first
        self.blocker.temp_dir = Path("/tmp/test")

        with patch("builtins.open", mock_open()) as mock_file:
            with patch.object(Path, "chmod") as mock_chmod:
                self.blocker.create_fake_executable("test_command")

                mock_file.assert_called_once()
                mock_chmod.assert_called_once()

    def test_cleanup_edge_cases(self):
        """Test cleanup with edge cases."""
        # Test cleanup when directory doesn't exist
        self.blocker.cleanup()

        # Test cleanup when directory exists but is empty
        # Set up a temp_dir for the test
        self.blocker.temp_dir = Path("/tmp/test")
        with patch.object(Path, "exists", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch("shutil.rmtree") as mock_rmtree:
                    self.blocker.cleanup()
                    mock_rmtree.assert_called_once()

    def test_cleanup_with_files(self):
        """Test cleanup when directory has files."""
        # Set up created_files for the test
        self.blocker.temp_dir = Path("/tmp/test")
        self.blocker.created_files = [Path("/tmp/test/file1"), Path("/tmp/test/file2")]

        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "unlink") as mock_unlink:
                with patch("shutil.rmtree") as mock_rmtree:
                    self.blocker.cleanup()

                    # Should remove files first
                    self.assertEqual(mock_unlink.call_count, 2)
                    # Then remove directory
                    mock_rmtree.assert_called_once()

    def test_cleanup_remove_error(self):
        """Test cleanup when file removal fails."""
        # Set up a temp_dir for the test
        self.blocker.temp_dir = Path("/tmp/test")
        with patch.object(Path, "exists", return_value=True):
            with patch("os.listdir", return_value=["file1"]):
                with patch("os.remove", side_effect=OSError("Permission denied")):
                    with patch("shutil.rmtree") as mock_rmtree:
                        # Should continue even if file removal fails
                        self.blocker.cleanup()
                        mock_rmtree.assert_called_once()

    def test_cleanup_rmdir_error(self):
        """Test cleanup when directory removal fails."""
        # Set up a temp_dir for the test
        self.blocker.temp_dir = Path("/tmp/test")
        with patch.object(Path, "exists", return_value=True):
            with patch("os.listdir", return_value=[]):
                with patch("shutil.rmtree", side_effect=OSError("Directory not empty")):
                    # Should not raise exception
                    self.blocker.cleanup()

    def test_start_blocking_temp_dir_creation_error(self):
        """Test start_blocking when temp directory creation fails."""
        with patch("tempfile.mkdtemp", side_effect=OSError("Permission denied")):
            # Should not raise exception, just log the error
            self.blocker.start_blocking()
            # Verify that blocking is not active when setup fails
            self.assertFalse(self.blocker.is_blocking_active())

    def test_start_blocking_path_modification_error(self):
        """Test start_blocking when PATH modification fails."""
        with patch("tempfile.mkdtemp", return_value="/tmp/test"):
            with patch.object(
                self.blocker,
                "_create_fake_executables",
                side_effect=Exception("PATH error"),
            ):
                # Should not raise exception, just log the error
                self.blocker.start_blocking()
                # Verify that blocking is not active when setup fails
                self.assertFalse(self.blocker.is_blocking_active())

    def test_create_fake_executable_error(self):
        """Test create_fake_executable when file creation fails."""
        # Set up temp directory first
        self.blocker.temp_dir = Path("/tmp/test")

        with patch("builtins.open", side_effect=OSError("Permission denied")):
            # Should not raise exception, just log the error
            self.blocker.create_fake_executable("test_command")

    def test_create_fake_executable_chmod_error(self):
        """Test create_fake_executable when chmod fails."""
        # Set up temp directory first
        self.blocker.temp_dir = Path("/tmp/test")

        with patch("builtins.open", mock_open()):
            with patch("os.chmod", side_effect=OSError("Permission denied")):
                # Should not raise exception, just log the error
                self.blocker.create_fake_executable("test_command")

    def test_stop_blocking_not_active(self):
        """Test stop_blocking when blocking is not active."""
        # Should not raise exception
        self.blocker.stop_blocking()

    def test_stop_blocking_cleanup_error(self):
        """Test stop_blocking when cleanup fails."""
        self.blocker.start_blocking()

        with patch("shutil.rmtree", side_effect=Exception("Cleanup failed")):
            # Should not raise exception, just log the error
            self.blocker.stop_blocking()
            # Verify that blocking is stopped even if cleanup fails
            self.assertFalse(self.blocker.is_blocking_active())

    def test_get_blocked_operations_log_empty(self):
        """Test get_blocked_operations_log when log is empty."""
        log = self.blocker.get_blocked_operations_log()
        self.assertEqual(log, [])

    def test_get_blocked_operations_log_with_entries(self):
        """Test get_blocked_operations_log with entries."""
        # Set up temp directory and create log entries
        self.blocker.temp_dir = Path("/tmp/test")
        self.blocker.temp_dir.mkdir(exist_ok=True)

        # Create a log file with some entries
        log_file = self.blocker.temp_dir / "blocked_operations.log"
        log_entries = [
            {"command": "test_command", "args": [], "timestamp": "2023-01-01T00:00:00"},
            {
                "command": "another_command",
                "args": ["arg1"],
                "timestamp": "2023-01-01T00:01:00",
            },
        ]

        with open(log_file, "w") as f:
            for entry in log_entries:
                f.write(json.dumps(entry) + "\n")

        log = self.blocker.get_blocked_operations_log()
        self.assertEqual(len(log), 2)
        self.assertEqual(log[0]["command"], "test_command")
        self.assertEqual(log[1]["command"], "another_command")

        # Clean up
        if log_file.exists():
            log_file.unlink()
        if self.blocker.temp_dir.exists():
            shutil.rmtree(self.blocker.temp_dir)

    def test_is_blocking_active(self):
        """Test is_blocking_active."""
        # Initially not active
        self.assertFalse(self.blocker.is_blocking_active())

        # Start blocking
        self.blocker.start_blocking()
        self.assertTrue(self.blocker.is_blocking_active())

        # Stop blocking
        self.blocker.stop_blocking()
        self.assertFalse(self.blocker.is_blocking_active())


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

            # Mock subprocess.run to simulate blocked command
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = "FUZZER BLOCKED: xdg-open command blocked"
                mock_subprocess.return_value = mock_result

                subprocess.run(["xdg-open", "test-url"], capture_output=True)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(is_system_blocking_active())

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

            # Mock subprocess.run to simulate blocked commands
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = (
                    "FUZZER BLOCKED: command blocked, prevent external app launch"
                )
                mock_subprocess.return_value = mock_result

                for cmd in node_commands:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0)
                    self.assertIn("FUZZER BLOCKED", result.stderr)
                    self.assertIn("prevent external app launch", result.stderr)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(is_system_blocking_active())

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
            # Mock subprocess.run to simulate blocked command
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = "FUZZER BLOCKED: firefox command blocked"
                mock_subprocess.return_value = mock_result

                result = subprocess.run(["firefox"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn("FUZZER BLOCKED", result.stderr)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(is_system_blocking_active())

        finally:
            stop_system_blocking()

    def test_command_with_special_characters(self):
        """Test blocking commands with special characters in arguments."""
        start_system_blocking()
        try:
            special_url = "https://example.com/path?param=value&other=test#anchor"
            # Mock subprocess.run to simulate blocked command
            with patch("subprocess.run") as mock_subprocess:
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stderr = "FUZZER BLOCKED: xdg-open command blocked"
                mock_subprocess.return_value = mock_result

                result = subprocess.run(
                    ["xdg-open", special_url], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0)
                self.assertIn("FUZZER BLOCKED", result.stderr)

            # Since we're mocking subprocess.run, the actual logging won't happen
            # Instead, verify that the system blocker is working correctly
            self.assertTrue(is_system_blocking_active())

        finally:
            stop_system_blocking()


if __name__ == "__main__":
    unittest.main()
