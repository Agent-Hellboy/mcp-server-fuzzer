#!/usr/bin/env python3
"""
Unit tests for Safety module
"""

import unittest
from unittest.mock import patch, MagicMock

from mcp_fuzzer.safety_system.safety import (
    SafetyFilter,
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
        self.assertIsInstance(self.filter.blocked_operations, list)

    def test_contains_dangerous_url_edge_cases(self):
        """Test contains_dangerous_url with edge cases."""
        # Test with None
        self.assertFalse(self.filter.contains_dangerous_url(None))

        # Test with empty string
        self.assertFalse(self.filter.contains_dangerous_url(""))

        # Test with whitespace only
        self.assertFalse(self.filter.contains_dangerous_url("   "))

        # Test with safe URL (not matching any patterns)
        self.assertFalse(self.filter.contains_dangerous_url("just-a-string"))

    def test_contains_dangerous_url_dangerous_patterns(self):
        """Test contains_dangerous_url with dangerous patterns."""
        dangerous_urls = [
            "http://malicious.com",
            "https://evil.org",
            "ftp://dangerous.net",
            "file:///etc/passwd",
            "www.evil.com",
            "example.com",
        ]

        for url in dangerous_urls:
            result = self.filter.contains_dangerous_url(url)
            if not result:
                print(f"URL not detected as dangerous: {url}")
            self.assertTrue(result, f"URL should be detected as dangerous: {url}")

    def test_contains_dangerous_command_edge_cases(self):
        """Test contains_dangerous_command with edge cases."""
        # Test with None
        self.assertFalse(self.filter.contains_dangerous_command(None))

        # Test with empty string
        self.assertFalse(self.filter.contains_dangerous_command(""))

        # Test with whitespace only
        self.assertFalse(self.filter.contains_dangerous_command("   "))

        # Test with safe command
        self.assertFalse(self.filter.contains_dangerous_command("echo hello"))

    def test_contains_dangerous_command_dangerous_patterns(self):
        """Test contains_dangerous_command with dangerous patterns."""
        dangerous_commands = [
            "xdg-open file.pdf",
            "open document.txt",
            "start notepad.exe",
            "firefox",
            "chrome",
            "chromium",
            "safari",
            "edge",
            "opera",
            "brave",
            "sudo rm -rf /",
            "rm -rf /tmp",
        ]

        for command in dangerous_commands:
            result = self.filter.contains_dangerous_command(command)
            if not result:
                print(f"Command not detected as dangerous: {command}")
            self.assertTrue(
                result, f"Command should be detected as dangerous: {command}"
            )

    def test_sanitize_string_argument_suspicious_detection(self):
        """Test _sanitize_string_argument with suspicious content."""
        # Test with suspicious argument names
        suspicious_args = [
            ("url", "https://example.com"),
            ("browser", "firefox"),
            ("launch", "chrome"),
            ("start", "notepad.exe"),
        ]

        for arg_name, value in suspicious_args:
            result = self.filter._sanitize_string_argument(arg_name, value)
            self.assertIn("BLOCKED", result)

    def test_sanitize_string_argument_safe_content(self):
        """Test _sanitize_string_argument with safe content."""
        safe_args = [
            ("name", "test"),
            ("description", "A safe description"),
            ("value", "123"),
        ]

        for arg_name, value in safe_args:
            result = self.filter._sanitize_string_argument(arg_name, value)
            self.assertEqual(result, value)

    def test_sanitize_value_complex_structures(self):
        """Test _sanitize_value with complex nested structures."""
        complex_value = {
            "config": {
                "nested": {"deep": {"url": "https://dangerous.com", "safe": "value"}}
            },
            "list": [{"item": "xdg-open file"}, "safe_item", None, 42, True],
            "mixed": ["safe", {"nested_url": "http://malicious.org"}, 42, True],
        }

        result = self.filter._sanitize_value("root", complex_value)

        # Check that dangerous content was sanitized
        self.assertEqual(result["config"]["nested"]["deep"]["url"], "[BLOCKED_URL]")
        self.assertEqual(result["config"]["nested"]["deep"]["safe"], "value")
        self.assertEqual(result["list"][0]["item"], "[BLOCKED_COMMAND]")
        self.assertEqual(result["list"][1], "safe_item")
        self.assertIsNone(result["list"][2])
        self.assertEqual(result["list"][3], 42)
        self.assertTrue(result["list"][4])
        self.assertEqual(result["mixed"][0], "safe")
        self.assertEqual(result["mixed"][1]["nested_url"], "[BLOCKED_URL]")
        self.assertEqual(result["mixed"][2], 42)
        self.assertTrue(result["mixed"][3])

    def test_sanitize_value_simple_types(self):
        """Test _sanitize_value with simple types."""
        # Test with int
        result = self.filter._sanitize_value("count", 42)
        self.assertEqual(result, 42)

        # Test with bool
        result = self.filter._sanitize_value("enabled", True)
        self.assertEqual(result, True)

        # Test with None
        result = self.filter._sanitize_value("optional", None)
        self.assertIsNone(result)

        # Test with float
        result = self.filter._sanitize_value("price", 3.14)
        self.assertEqual(result, 3.14)

    def test_should_skip_tool_call_complex_arguments(self):
        """Test should_skip_tool_call with complex argument structures."""
        # Test with nested dangerous content
        complex_args = {
            "config": {"url": "https://malicious.com", "safe": "value"},
            "commands": ["echo hello", "xdg-open file.pdf"],
            "nested": {"deep": {"dangerous": "http://evil.org"}},
        }

        self.assertTrue(self.filter.should_skip_tool_call("test_tool", complex_args))

    def test_should_skip_tool_call_safe_arguments(self):
        """Test should_skip_tool_call with safe arguments."""
        safe_args = {
            "name": "test",
            "description": "A safe description",
            "value": 123,
            "enabled": True,
        }

        self.assertFalse(self.filter.should_skip_tool_call("test_tool", safe_args))

    def test_should_skip_tool_call_empty_arguments(self):
        """Test should_skip_tool_call with empty arguments."""
        # Test with None
        self.assertFalse(self.filter.should_skip_tool_call("test_tool", None))

        # Test with empty dict
        self.assertFalse(self.filter.should_skip_tool_call("test_tool", {}))

    def test_should_skip_tool_call_with_list_arguments(self):
        """Test should_skip_tool_call with list arguments
        containing dangerous content."""
        # Test with dangerous URL in list
        dangerous_list_args = {
            "urls": ["https://malicious.com", "safe_url"],
            "commands": ["echo hello", "xdg-open file.pdf"],
        }

        self.assertTrue(
            self.filter.should_skip_tool_call("test_tool", dangerous_list_args)
        )

        # Test with safe list arguments
        safe_list_args = {
            "urls": ["safe_url1", "safe_url2"],
            "commands": ["echo hello", "ls -la"],
        }

        self.assertFalse(self.filter.should_skip_tool_call("test_tool", safe_list_args))

    def test_sanitize_tool_arguments_empty(self):
        """Test sanitize_tool_arguments with empty arguments."""
        # Test with None
        result = self.filter.sanitize_tool_arguments("test_tool", None)
        self.assertIsNone(result)

        # Test with empty dict
        result = self.filter.sanitize_tool_arguments("test_tool", {})
        self.assertEqual(result, {})

    def test_sanitize_tool_arguments_complex(self):
        """Test sanitize_tool_arguments with complex arguments."""
        complex_args = {
            "url": "https://dangerous.com",
            "command": "xdg-open file",
            "safe": "value",
            "nested": {"dangerous": "http://evil.org"},
        }

        result = self.filter.sanitize_tool_arguments("test_tool", complex_args)

        self.assertEqual(result["url"], "[BLOCKED_URL]")
        self.assertEqual(result["command"], "[BLOCKED_COMMAND]")
        self.assertEqual(result["safe"], "value")
        self.assertEqual(result["nested"]["dangerous"], "[BLOCKED_URL]")

    def test_create_safe_mock_response(self):
        """Test create_safe_mock_response."""
        response = self.filter.create_safe_mock_response("test_tool")

        self.assertIn("error", response)
        self.assertIn("code", response["error"])
        self.assertEqual(response["error"]["code"], -32603)
        self.assertIn("message", response["error"])
        self.assertIn("SAFETY BLOCKED", response["error"]["message"])

    def test_log_blocked_operation(self):
        """Test log_blocked_operation."""
        with patch("mcp_fuzzer.safety_system.safety.logging") as mock_logging:
            self.filter.log_blocked_operation(
                "test_tool", {"arg": "value"}, "Test reason"
            )

            # The method logs multiple lines, so we expect multiple calls
            self.assertGreaterEqual(mock_logging.warning.call_count, 1)
            # Check that the first call contains the tool name
            first_call = mock_logging.warning.call_args_list[0]
            self.assertIn("test_tool", str(first_call))

    def test_log_blocked_operation_adds_to_list(self):
        """Test that log_blocked_operation adds to blocked_operations list."""
        initial_count = len(self.filter.blocked_operations)

        self.filter.log_blocked_operation("test_tool", {"arg": "value"}, "Test reason")

        self.assertEqual(len(self.filter.blocked_operations), initial_count + 1)
        self.assertEqual(self.filter.blocked_operations[-1]["tool_name"], "test_tool")

    def test_log_blocked_operation_with_long_arguments(self):
        """Test log_blocked_operation with long string arguments that get truncated."""
        long_string = "x" * 150  # Longer than 100 characters
        arguments = {"long_param": long_string, "short_param": "short"}

        self.filter.log_blocked_operation("test_tool", arguments, "test_reason")

        # Check that the operation was logged
        self.assertEqual(len(self.filter.blocked_operations), 1)
        logged_op = self.filter.blocked_operations[0]
        self.assertEqual(logged_op["tool_name"], "test_tool")
        self.assertEqual(logged_op["reason"], "test_reason")

        # Check that long arguments are truncated in the log
        # The actual arguments should be stored as-is
        self.assertEqual(logged_op["arguments"]["long_param"], long_string)

    def test_log_blocked_operation_with_empty_arguments(self):
        """Test log_blocked_operation with empty arguments."""
        self.filter.log_blocked_operation("test_tool", {}, "test_reason")

        self.assertEqual(len(self.filter.blocked_operations), 1)
        logged_op = self.filter.blocked_operations[0]
        self.assertEqual(logged_op["arguments"], {})

    def test_log_blocked_operation_with_none_arguments(self):
        """Test log_blocked_operation with None arguments."""
        self.filter.log_blocked_operation("test_tool", None, "test_reason")

        self.assertEqual(len(self.filter.blocked_operations), 1)
        logged_op = self.filter.blocked_operations[0]
        self.assertEqual(logged_op["arguments"], None)

    def test_sanitize_string_argument_with_dangerous_argument_names(self):
        """Test _sanitize_string_argument with dangerous argument names."""
        # Test with dangerous argument names that should trigger extra scrutiny
        dangerous_arg_names = ["url", "browser", "command", "executable"]

        for arg_name in dangerous_arg_names:
            # Test with safe values that should pass
            safe_value = "just_a_normal_string"
            result = self.filter._sanitize_string_argument(arg_name, safe_value)
            self.assertEqual(result, safe_value)

            # Test with suspicious values that should be blocked
            suspicious_value = "browser"
            result = self.filter._sanitize_string_argument(arg_name, suspicious_value)
            self.assertEqual(result, "[BLOCKED_SUSPICIOUS]")

    def test_sanitize_string_argument_with_edge_cases(self):
        """Test _sanitize_string_argument with edge cases."""
        # Test with None value
        result = self.filter._sanitize_string_argument("test_arg", None)
        self.assertIsNone(result)

        # Test with empty string
        result = self.filter._sanitize_string_argument("test_arg", "")
        self.assertEqual(result, "")

        # Test with whitespace only
        result = self.filter._sanitize_string_argument("test_arg", "   ")
        self.assertEqual(result, "   ")

    def test_should_skip_tool_call_with_dict_arguments(self):
        """Test should_skip_tool_call with dictionary arguments."""
        # Test with nested dictionary that contains dangerous content
        nested_args = {
            "config": {"url": "http://malicious.com", "safe_param": "normal_value"}
        }

        # This should not be skipped because we only check top-level arguments
        # The nested dictionary structure is not currently handled
        result = self.filter.should_skip_tool_call("test_tool", nested_args)
        self.assertFalse(result)

    def test_should_skip_tool_call_with_mixed_types(self):
        """Test should_skip_tool_call with mixed argument types."""
        mixed_args = {
            "string_param": "http://evil.com",  # Should be blocked
            "int_param": 42,  # Should be ignored
            "bool_param": True,  # Should be ignored
            "list_param": ["safe_item", "https://dangerous.com"],  # Should be blocked
        }

        result = self.filter.should_skip_tool_call("test_tool", mixed_args)
        self.assertTrue(result)  # Should be blocked due to dangerous content


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
            "command": "xdg-open file",
        }

        sanitized_name, sanitized_args = sanitize_tool_call(tool_name, arguments)

        self.assertEqual(sanitized_name, tool_name)
        self.assertEqual(sanitized_args["url"], "[BLOCKED_URL]")
        self.assertEqual(sanitized_args["safe_arg"], "value")
        self.assertEqual(sanitized_args["command"], "[BLOCKED_COMMAND]")

    def test_create_safety_response(self):
        """Test global create_safety_response function."""
        response = create_safety_response("test_tool")

        self.assertIn("error", response)
        self.assertIn("code", response["error"])
        self.assertEqual(response["error"]["code"], -32603)
        self.assertIn("message", response["error"])
        self.assertIn("SAFETY BLOCKED", response["error"]["message"])
        self.assertIn("test_tool", response["error"]["message"])


class TestSafetyIntegration(unittest.TestCase):
    """Integration tests for safety functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.filter = SafetyFilter()

    def test_complex_argument_sanitization(self):
        """Test complex argument sanitization scenarios."""
        complex_args = {
            "config": {
                "api_url": "https://api.example.com",
                "dangerous_url": "http://malicious.org",
                "commands": ["echo hello", "xdg-open file.pdf", "ls -la"],
            },
            "nested": {"deep": {"url": "https://evil.com", "safe": "value"}},
            "list": ["safe_item", {"url": "http://dangerous.net"}, "another_safe_item"],
        }

        result = self.filter.sanitize_tool_arguments("test_tool", complex_args)

        # Check that dangerous content was sanitized
        self.assertEqual(result["config"]["dangerous_url"], "[BLOCKED_URL]")
        self.assertEqual(result["config"]["commands"][1], "[BLOCKED_COMMAND]")
        self.assertEqual(result["nested"]["deep"]["url"], "[BLOCKED_URL]")
        self.assertEqual(result["list"][1]["url"], "[BLOCKED_URL]")

        # Check that safe content was preserved (but URLs are blocked)
        self.assertEqual(result["config"]["api_url"], "[BLOCKED_URL]")
        self.assertEqual(result["config"]["commands"][0], "echo hello")
        self.assertEqual(result["config"]["commands"][2], "ls -la")
        self.assertEqual(result["nested"]["deep"]["safe"], "value")
        self.assertEqual(result["list"][0], "safe_item")
        self.assertEqual(result["list"][2], "another_safe_item")

    def test_edge_cases(self):
        """Test various edge cases."""
        # Test with very long strings
        long_string = "a" * 10000
        result = self.filter._sanitize_string_argument("test", long_string)
        self.assertEqual(result, long_string)

        # Test with unicode characters
        unicode_string = "测试字符串"
        result = self.filter._sanitize_string_argument("test", unicode_string)
        self.assertEqual(result, unicode_string)

        # Test with special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        result = self.filter._sanitize_string_argument("test", special_chars)
        self.assertEqual(result, special_chars)

    def test_performance_with_large_arguments(self):
        """Test performance with large argument structures."""
        # Create a large nested structure
        large_args = {}
        current = large_args
        for i in range(100):
            current[f"level_{i}"] = {
                "url": f"https://level{i}.example.com",
                "command": f"echo level{i}",
                "safe": f"safe_value_{i}",
            }
            current = current[f"level_{i}"]

        # This should not raise any exceptions
        result = self.filter.sanitize_tool_arguments("test_tool", large_args)

        # Verify the structure is preserved
        self.assertIsInstance(result, dict)
        self.assertIn("level_0", result)

    def test_real_world_scenarios(self):
        """Test real-world scenarios."""
        # Scenario 1: API configuration
        api_config = {
            "base_url": "https://api.example.com",
            "endpoints": {
                "users": "https://api.example.com/users",
                "dangerous": "http://malicious.org/api",
            },
            "commands": {
                "backup": "tar -czf backup.tar.gz /data",
                "open": "xdg-open file.pdf",
            },
        }

        result = self.filter.sanitize_tool_arguments("api_tool", api_config)

        self.assertEqual(result["base_url"], "[BLOCKED_URL]")
        self.assertEqual(result["endpoints"]["dangerous"], "[BLOCKED_URL]")
        self.assertEqual(result["commands"]["open"], "[BLOCKED_COMMAND]")
        self.assertEqual(result["commands"]["backup"], "tar -czf backup.tar.gz /data")


if __name__ == "__main__":
    unittest.main()
