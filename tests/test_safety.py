#!/usr/bin/env python3
"""
Unit tests for the safety module.
"""

import unittest
from unittest.mock import patch, MagicMock

from mcp_fuzzer.safety import (
    SafetyFilter,
    safety_filter,
    is_safe_tool_call,
    sanitize_tool_call,
    create_safety_response,
)


class TestSafetyFilter(unittest.TestCase):
    """Test cases for SafetyFilter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.filter = SafetyFilter()

    def test_init(self):
        """Test SafetyFilter initialization."""
        self.assertIsInstance(self.filter.dangerous_url_patterns, list)
        self.assertIsInstance(self.filter.dangerous_command_patterns, list)
        self.assertIsInstance(self.filter.dangerous_argument_names, list)

        # Check some expected patterns
        self.assertIn(r"https?://", self.filter.dangerous_url_patterns)
        self.assertIn(r"xdg-open", self.filter.dangerous_command_patterns)
        self.assertIn("url", self.filter.dangerous_argument_names)

    def test_contains_dangerous_url(self):
        """Test URL detection."""
        # Dangerous URLs
        dangerous_urls = [
            "https://example.com",
            "http://test.org",
            "ftp://files.example.com",
            "www.google.com",
            "example.com",
            "test.org",
            "subdomain.example.co.uk",
        ]

        for url in dangerous_urls:
            with self.subTest(url=url):
                self.assertTrue(self.filter.contains_dangerous_url(url))

        # Safe strings
        safe_strings = [
            "local_file.txt",
            "config_value",
            "123456",
            "/path/to/file",
            "user@hostname",
            "",
        ]

        for string in safe_strings:
            with self.subTest(string=string):
                self.assertFalse(self.filter.contains_dangerous_url(string))

    def test_contains_dangerous_command(self):
        """Test command detection."""
        # Dangerous commands (based on actual patterns in safety.py)
        dangerous_commands = [
            "xdg-open file.pdf",
            "open /Applications/Safari.app",
            "start notepad.exe",
            "firefox.exe --new-tab",
            "chrome",
            "firefox",
            "safari",
            "rm -rf /",
            "sudo rm important.txt",
            "shutdown now",
            "reboot",
            "program.exe",
            "app.msi",
            "installer.dmg",
        ]

        for cmd in dangerous_commands:
            with self.subTest(cmd=cmd):
                self.assertTrue(self.filter.contains_dangerous_command(cmd))

        # Safe commands
        safe_commands = [
            "ls -la",
            "echo hello",
            "cat file.txt",
            "mkdir new_directory",
            "cd /home/user",
            "python script.py",
            "node server.js",
            "wget",  # Just "wget" without args is safer
            "curl",  # Just "curl" without args is safer
            "",
        ]

        for cmd in safe_commands:
            with self.subTest(cmd=cmd):
                self.assertFalse(self.filter.contains_dangerous_command(cmd))

    def test_sanitize_string_argument_suspicious_detection(self):
        """Test suspicious argument detection in sanitization."""
        # Test dangerous argument names with suspicious content
        # Note: URL and command detection have priority over suspicious detection
        dangerous_arg_cases = [
            ("url", "http://example.com", "[BLOCKED_URL]"),
            ("command", "xdg-open file", "[BLOCKED_COMMAND]"),
            ("url", "browser://something", "[BLOCKED_SUSPICIOUS]"),
            ("command", "open file.app", "[BLOCKED_COMMAND]"),
            ("path", "launch.exe", "[BLOCKED_COMMAND]"),
            ("script", "start.exe", "[BLOCKED_COMMAND]"),
        ]

        for arg_name, value, expected in dangerous_arg_cases:
            with self.subTest(arg_name=arg_name, value=value):
                result = self.filter._sanitize_string_argument(arg_name, value)
                self.assertEqual(result, expected)

        # Safe arguments should pass through
        safe_cases = [
            ("normal_arg", "safe_value", "safe_value"),
            ("config", "setting", "setting"),
            ("number", "123", "123"),
            ("path", "/safe/local/path", "/safe/local/path"),
            ("", "value", "value"),
        ]

        for arg_name, value, expected in safe_cases:
            with self.subTest(arg_name=arg_name, value=value):
                result = self.filter._sanitize_string_argument(arg_name, value)
                self.assertEqual(result, expected)

    def test_sanitize_tool_arguments(self):
        """Test tool argument sanitization."""
        # Test with dangerous arguments
        dangerous_args = {
            "url": "https://malicious.com",
            "command": "xdg-open file.pdf",
            "script": "browser.exe",
            "safe_arg": "normal_value",
        }

        sanitized = self.filter.sanitize_tool_arguments("test_tool", dangerous_args)

        self.assertEqual(sanitized["url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized["command"], "[BLOCKED_COMMAND]")
        self.assertEqual(sanitized["script"], "[BLOCKED_COMMAND]")  # .exe pattern
        self.assertEqual(sanitized["safe_arg"], "normal_value")

        # Test with nested arguments (full recursive sanitization now supported)
        nested_args = {
            "config": {
                "url": "http://example.com",  # Should be sanitized now
                "safe": "value",
                "commands": {
                    "open": "xdg-open file.pdf",  # Should be sanitized
                    "safe": "echo hello",
                },
            },
            "list_arg": ["safe", "https://danger.com", "normal"],
            "nested_list": [
                {"inner_url": "https://malicious.com"},  # Should be sanitized
                "safe_string",
            ],
        }

        sanitized = self.filter.sanitize_tool_arguments("test_tool", nested_args)

        # Nested dict URLs are now sanitized
        self.assertEqual(sanitized["config"]["url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized["config"]["safe"], "value")
        self.assertEqual(sanitized["config"]["commands"]["open"], "[BLOCKED_COMMAND]")
        self.assertEqual(sanitized["config"]["commands"]["safe"], "echo hello")

        # List items are sanitized
        self.assertEqual(sanitized["list_arg"][0], "safe")
        self.assertEqual(sanitized["list_arg"][1], "[BLOCKED_URL]")
        self.assertEqual(sanitized["list_arg"][2], "normal")

        # Nested objects in lists are sanitized
        self.assertEqual(sanitized["nested_list"][0]["inner_url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized["nested_list"][1], "safe_string")

    def test_should_skip_tool_call(self):
        """Test tool call skipping logic."""
        # Safe tool calls
        safe_calls = [
            ("safe_tool", {}),
            ("get_config", {"key": "value"}),
            ("list_files", {"path": "/safe/path"}),
            ("safe_tool", {"arg": "normal_value"}),
        ]

        for tool_name, args in safe_calls:
            with self.subTest(tool=tool_name, args=args):
                self.assertFalse(self.filter.should_skip_tool_call(tool_name, args))

        # Dangerous tool calls
        dangerous_calls = [
            ("tool", {"url": "https://malicious.com"}),
            ("tool", {"command": "xdg-open file"}),
            ("tool", {"script": "firefox.exe"}),  # Will be detected
            ("tool", {"path": "file:///etc/passwd"}),
        ]

        for tool_name, args in dangerous_calls:
            with self.subTest(tool=tool_name, args=args):
                self.assertTrue(self.filter.should_skip_tool_call(tool_name, args))

    @patch("mcp_fuzzer.safety.logging")
    def test_log_blocked_operation(self, mock_logging):
        """Test operation logging."""
        tool_name = "test_tool"
        arguments = {"url": "https://example.com"}
        reason = "Test blocking"

        self.filter.log_blocked_operation(tool_name, arguments, reason)

        # Verify logging was called (method makes multiple warning calls)
        self.assertTrue(mock_logging.warning.called)
        self.assertGreaterEqual(mock_logging.warning.call_count, 1)

        # Check that tool name and reason appear in the logged messages
        all_calls = mock_logging.warning.call_args_list
        call_messages = [str(call) for call in all_calls]
        combined_message = " ".join(call_messages)
        self.assertIn(tool_name, combined_message)
        self.assertIn(reason, combined_message)

    def test_create_safe_mock_response(self):
        """Test safe mock response creation."""
        tool_name = "test_tool"
        response = self.filter.create_safe_mock_response(tool_name)

        self.assertIsInstance(response, dict)
        self.assertIn("content", response)
        self.assertIsInstance(response["content"], list)
        self.assertEqual(response["content"][0]["type"], "text")
        self.assertIn("SAFETY", response["content"][0]["text"])
        self.assertIn(tool_name, response["content"][0]["text"])


class TestGlobalFunctions(unittest.TestCase):
    """Test cases for global convenience functions."""

    def test_is_safe_tool_call(self):
        """Test global is_safe_tool_call function."""
        # Safe calls
        self.assertTrue(is_safe_tool_call("safe_tool", {}))
        self.assertTrue(is_safe_tool_call("tool", {"arg": "safe_value"}))

        # Dangerous calls
        self.assertFalse(is_safe_tool_call("tool", {"url": "https://danger.com"}))
        self.assertFalse(is_safe_tool_call("tool", {"command": "xdg-open file"}))

    def test_sanitize_tool_call(self):
        """Test global sanitize_tool_call function."""
        tool_name = "test_tool"
        arguments = {
            "url": "https://example.com",
            "safe_arg": "value",
            "command": "firefox browser",
        }

        sanitized_name, sanitized_args = sanitize_tool_call(tool_name, arguments)

        self.assertEqual(sanitized_name, tool_name)
        self.assertEqual(sanitized_args["url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized_args["safe_arg"], "value")
        # firefox browser -> suspicious
        self.assertEqual(sanitized_args["command"], "[BLOCKED_SUSPICIOUS]")

    def test_create_safety_response(self):
        """Test global create_safety_response function."""
        tool_name = "test_tool"
        response = create_safety_response(tool_name)

        self.assertIsInstance(response, dict)
        self.assertIn("content", response)
        self.assertIn(tool_name, response["content"][0]["text"])


class TestSafetyIntegration(unittest.TestCase):
    """Integration tests for safety functionality."""

    def test_complex_argument_sanitization(self):
        """Test sanitization of complex nested arguments."""
        complex_args = {
            "config": {
                "urls": [
                    "https://malicious.com",
                    "safe_config_value",
                    "http://another-danger.org",
                ],
                "commands": {"open": "xdg-open file.pdf", "safe": "echo hello"},
            },
            "metadata": {
                "scripts": ["eval('danger')", "safe_script"],
                "paths": ["file:///etc/passwd", "/safe/path"],
            },
        }

        filter_obj = SafetyFilter()
        sanitized = filter_obj.sanitize_tool_arguments("test_tool", complex_args)

        # Check URLs in lists (list sanitization works)
        self.assertEqual(sanitized["config"]["urls"][0], "[BLOCKED_URL]")
        self.assertEqual(sanitized["config"]["urls"][1], "safe_config_value")
        self.assertEqual(sanitized["config"]["urls"][2], "[BLOCKED_URL]")

        # Check commands in nested dict (now properly sanitized)
        self.assertEqual(sanitized["config"]["commands"]["open"], "[BLOCKED_COMMAND]")
        self.assertEqual(sanitized["config"]["commands"]["safe"], "echo hello")

        # Check scripts and paths in lists (now properly sanitized)
        # eval not dangerous pattern
        self.assertEqual(sanitized["metadata"]["scripts"][0], "eval('danger')")
        self.assertEqual(sanitized["metadata"]["scripts"][1], "safe_script")
        # file:// is URL pattern
        self.assertEqual(sanitized["metadata"]["paths"][0], "[BLOCKED_URL]")
        self.assertEqual(sanitized["metadata"]["paths"][1], "/safe/path")

    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        filter_obj = SafetyFilter()

        # Empty arguments
        self.assertFalse(filter_obj.should_skip_tool_call("tool", {}))

        # None values
        args_with_none = {"arg1": None, "arg2": "value"}
        sanitized = filter_obj.sanitize_tool_arguments("test_tool", args_with_none)
        self.assertIsNone(sanitized["arg1"])
        self.assertEqual(sanitized["arg2"], "value")

        # Very long strings
        long_url = "https://" + "a" * 1000 + ".com"
        self.assertTrue(filter_obj.contains_dangerous_url(long_url))

        # Mixed case
        mixed_case_url = "HTTPS://EXAMPLE.COM"
        self.assertTrue(filter_obj.contains_dangerous_url(mixed_case_url))

    def test_performance_with_large_arguments(self):
        """Test performance with large argument sets."""
        filter_obj = SafetyFilter()

        # Create large argument set
        large_args = {}
        for i in range(100):
            large_args[f"arg_{i}"] = f"safe_value_{i}"

        # Add some dangerous values
        large_args["dangerous_url"] = "https://malicious.com"
        large_args["dangerous_cmd"] = "xdg-open file"

        # Test that it handles large sets efficiently
        sanitized = filter_obj.sanitize_tool_arguments("test_tool", large_args)

        self.assertEqual(len(sanitized), len(large_args))
        self.assertEqual(sanitized["dangerous_url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized["dangerous_cmd"], "[BLOCKED_COMMAND]")

        # Check that safe values are preserved
        for i in range(100):
            self.assertEqual(sanitized[f"arg_{i}"], f"safe_value_{i}")

    def test_real_world_scenarios(self):
        """Test with real-world MCP tool scenarios."""
        filter_obj = SafetyFilter()

        # Scenario 1: Browser opening tool
        browser_args = {"url": "https://tally.so/r/mYB6av", "new_tab": True}
        self.assertTrue(filter_obj.should_skip_tool_call("open_browser", browser_args))

        # Scenario 2: File operation tool
        file_args = {"path": "/safe/local/file.txt", "mode": "read"}
        self.assertFalse(filter_obj.should_skip_tool_call("read_file", file_args))

        # Scenario 3: System command tool
        system_args = {"command": "ls -la /home/user", "working_dir": "/home/user"}
        self.assertFalse(filter_obj.should_skip_tool_call("run_command", system_args))

        # Scenario 4: Dangerous system command with URL
        dangerous_system_args = {
            "command": "xdg-open https://malicious.com",
            "shell": True,
        }
        self.assertTrue(
            filter_obj.should_skip_tool_call("run_command", dangerous_system_args)
        )

        # Scenario 5: Tool with dangerous URL argument
        url_args = {"url": "https://example.com", "target": "_blank"}
        self.assertTrue(filter_obj.should_skip_tool_call("open_url", url_args))


if __name__ == "__main__":
    unittest.main()
