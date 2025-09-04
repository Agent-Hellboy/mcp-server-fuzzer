#!/usr/bin/env python3
"""
Unit tests for Safety module
"""

import pytest
from unittest.mock import patch, MagicMock

from mcp_fuzzer.safety_system.safety import (
    SafetyFilter,
    is_safe_tool_call,
    sanitize_tool_call,
    create_safety_response,
)

pytestmark = [pytest.mark.unit, pytest.mark.safety_system]


@pytest.fixture
def safety_filter():
    """Fixture for SafetyFilter test cases."""
    return SafetyFilter()


def test_init(safety_filter):
    """Test SafetyFilter initialization."""
    assert isinstance(safety_filter.dangerous_url_patterns, list)
    assert isinstance(safety_filter.dangerous_command_patterns, list)
    assert isinstance(safety_filter.dangerous_argument_names, set)
    assert isinstance(safety_filter.blocked_operations, list)


def test_contains_dangerous_url_edge_cases(safety_filter):
    """Test contains_dangerous_url with edge cases."""
    # Test with None
    assert not safety_filter.contains_dangerous_url(None)

    # Test with empty string
    assert not safety_filter.contains_dangerous_url("")

    # Test with whitespace only
    assert not safety_filter.contains_dangerous_url("   ")

    # Test with safe URL (not matching any patterns)
    assert not safety_filter.contains_dangerous_url("just-a-string")


def test_contains_dangerous_url_dangerous_patterns(safety_filter):
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
        result = safety_filter.contains_dangerous_url(url)
        if not result:
            print(f"URL not detected as dangerous: {url}")
        assert result, f"URL should be detected as dangerous: {url}"


def test_contains_dangerous_command_edge_cases(safety_filter):
    """Test contains_dangerous_command with edge cases."""
    # Test with None
    assert not safety_filter.contains_dangerous_command(None)

    # Test with empty string
    assert not safety_filter.contains_dangerous_command("")

    # Test with whitespace only
    assert not safety_filter.contains_dangerous_command("   ")

    # Test with safe command
    assert not safety_filter.contains_dangerous_command("echo hello")


def test_contains_dangerous_command_dangerous_patterns(safety_filter):
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
        result = safety_filter.contains_dangerous_command(command)
        if not result:
            print(f"Command not detected as dangerous: {command}")
        assert result, f"Command should be detected as dangerous: {command}"


def test_sanitize_string_argument_suspicious_detection(safety_filter):
    """Test _sanitize_string_argument with suspicious content."""
    # Test with suspicious argument names
    suspicious_args = [
        ("url", "https://example.com"),
        ("browser", "firefox"),
        ("launch", "chrome"),
        ("start", "notepad.exe"),
    ]

    for arg_name, value in suspicious_args:
        result = safety_filter._sanitize_string_argument(arg_name, value)
        assert "BLOCKED" in result


def test_sanitize_string_argument_safe_content(safety_filter):
    """Test _sanitize_string_argument with safe content."""
    safe_args = [
        ("name", "test"),
        ("description", "A safe description"),
        ("value", "123"),
    ]

    for arg_name, value in safe_args:
        result = safety_filter._sanitize_string_argument(arg_name, value)
        assert result == value


def test_sanitize_value_complex_structures(safety_filter):
    """Test _sanitize_value with complex nested structures."""
    complex_value = {
        "config": {
            "nested": {"deep": {"url": "https://dangerous.com", "safe": "value"}}
        },
        "list": [{"item": "xdg-open file"}, "safe_item", None, 42, True],
        "mixed": ["safe", {"nested_url": "http://malicious.org"}, 42, True],
    }

    result = safety_filter._sanitize_value("root", complex_value)

    # Check that dangerous content was sanitized
    assert result["config"]["nested"]["deep"]["url"] == "[BLOCKED_URL]"
    assert result["config"]["nested"]["deep"]["safe"] == "value"
    assert result["list"][0]["item"] == "[BLOCKED_COMMAND]"
    assert result["list"][1] == "safe_item"
    assert result["list"][2] is None
    assert result["list"][3] == 42
    assert result["list"][4] is True
    assert result["mixed"][0] == "safe"
    assert result["mixed"][1]["nested_url"] == "[BLOCKED_URL]"
    assert result["mixed"][2] == 42
    assert result["mixed"][3] is True


def test_sanitize_value_simple_types(safety_filter):
    """Test _sanitize_value with simple types."""
    # Test with int
    result = safety_filter._sanitize_value("count", 42)
    assert result == 42

    # Test with bool
    result = safety_filter._sanitize_value("enabled", True)
    assert result is True

    # Test with None
    result = safety_filter._sanitize_value("optional", None)
    assert result is None

    # Test with float
    result = safety_filter._sanitize_value("price", 3.14)
    assert result == 3.14


def test_should_skip_tool_call_complex_arguments(safety_filter):
    """Test should_skip_tool_call with complex argument structures."""
    # Test with nested dangerous content
    complex_args = {
        "config": {"url": "https://malicious.com", "safe": "value"},
        "commands": ["echo hello", "xdg-open file.pdf"],
        "nested": {"deep": {"dangerous": "http://evil.org"}},
    }

    assert safety_filter.should_skip_tool_call("test_tool", complex_args)


def test_should_skip_tool_call_safe_arguments(safety_filter):
    """Test should_skip_tool_call with safe arguments."""
    safe_args = {
        "name": "test",
        "description": "A safe description",
        "value": 123,
        "enabled": True,
    }

    assert not safety_filter.should_skip_tool_call("test_tool", safe_args)


def test_should_skip_tool_call_empty_arguments(safety_filter):
    """Test should_skip_tool_call with empty arguments."""
    # Test with None
    assert not safety_filter.should_skip_tool_call("test_tool", None)

    # Test with empty dict
    assert not safety_filter.should_skip_tool_call("test_tool", {})


def test_should_skip_tool_call_with_list_arguments(safety_filter):
    """Test should_skip_tool_call with list arguments
    containing dangerous content."""
    # Test with dangerous URL in list
    dangerous_list_args = {
        "urls": ["https://malicious.com", "safe_url"],
        "commands": ["echo hello", "xdg-open file.pdf"],
    }

    assert safety_filter.should_skip_tool_call("test_tool", dangerous_list_args)

    # Test with safe list arguments
    safe_list_args = {
        "urls": ["safe_url1", "safe_url2"],
        "commands": ["echo hello", "ls -la"],
    }

    assert not safety_filter.should_skip_tool_call("test_tool", safe_list_args)


def test_sanitize_tool_arguments_empty(safety_filter):
    """Test sanitize_tool_arguments with empty arguments."""
    # Test with None
    result = safety_filter.sanitize_tool_arguments("test_tool", None)
    assert result is None

    # Test with empty dict
    result = safety_filter.sanitize_tool_arguments("test_tool", {})
    assert result == {}


def test_sanitize_tool_arguments_complex(safety_filter):
    """Test sanitize_tool_arguments with complex arguments."""
    complex_args = {
        "url": "https://dangerous.com",
        "command": "xdg-open file",
        "safe": "value",
        "nested": {"dangerous": "http://evil.org"},
    }

    result = safety_filter.sanitize_tool_arguments("test_tool", complex_args)

    assert result["url"] == "[BLOCKED_URL]"
    assert result["command"] == "[BLOCKED_COMMAND]"
    assert result["safe"] == "value"
    assert result["nested"]["dangerous"] == "[BLOCKED_URL]"


def test_create_safe_mock_response(safety_filter):
    """Test create_safe_mock_response."""
    response = safety_filter.create_safe_mock_response("test_tool")

    assert "error" in response
    assert "code" in response["error"]
    assert response["error"]["code"] == -32603
    assert "message" in response["error"]
    assert "SAFETY BLOCKED" in response["error"]["message"]


def test_log_blocked_operation(safety_filter):
    """Test log_blocked_operation."""
    with patch("mcp_fuzzer.safety_system.safety.logging") as mock_logging:
        safety_filter.log_blocked_operation(
            "test_tool", {"arg": "value"}, "Test reason"
        )

        # The method logs multiple lines, so we expect multiple calls
        assert mock_logging.warning.call_count >= 1
        # Check that the first call contains the tool name
        first_call = mock_logging.warning.call_args_list[0]
        assert "test_tool" in str(first_call)


def test_log_blocked_operation_adds_to_list(safety_filter):
    """Test that log_blocked_operation adds to blocked_operations list."""
    initial_count = len(safety_filter.blocked_operations)

    safety_filter.log_blocked_operation("test_tool", {"arg": "value"}, "Test reason")

    assert len(safety_filter.blocked_operations) == initial_count + 1
    assert safety_filter.blocked_operations[-1]["tool_name"] == "test_tool"


def test_log_blocked_operation_with_long_arguments(safety_filter):
    """Test log_blocked_operation with long string arguments that get truncated."""
    long_string = "x" * 150  # Longer than 100 characters
    arguments = {"long_param": long_string, "short_param": "short"}

    safety_filter.log_blocked_operation("test_tool", arguments, "test_reason")

    # Check that the operation was logged
    assert len(safety_filter.blocked_operations) == 1
    logged_op = safety_filter.blocked_operations[0]
    assert logged_op["tool_name"] == "test_tool"
    assert logged_op["reason"] == "test_reason"

    # Check that long arguments are truncated in the log
    # The actual arguments should be stored as-is
    assert logged_op["arguments"]["long_param"] == long_string


def test_log_blocked_operation_with_empty_arguments(safety_filter):
    """Test log_blocked_operation with empty arguments."""
    safety_filter.log_blocked_operation("test_tool", {}, "test_reason")

    assert len(safety_filter.blocked_operations) == 1
    logged_op = safety_filter.blocked_operations[0]
    assert logged_op["arguments"] == {}


def test_log_blocked_operation_with_none_arguments(safety_filter):
    """Test log_blocked_operation with None arguments."""
    safety_filter.log_blocked_operation("test_tool", None, "test_reason")

    assert len(safety_filter.blocked_operations) == 1
    logged_op = safety_filter.blocked_operations[0]
    assert logged_op["arguments"] is None


def test_sanitize_string_argument_with_dangerous_argument_names(safety_filter):
    """Test _sanitize_string_argument with dangerous argument names."""
    # Test with dangerous argument names that should trigger extra scrutiny
    dangerous_arg_names = ["url", "browser", "command", "executable"]

    for arg_name in dangerous_arg_names:
        # Test with safe values that should pass
        safe_value = "just_a_normal_string"
        result = safety_filter._sanitize_string_argument(arg_name, safe_value)
        assert result == safe_value

        # Test with suspicious values that should be blocked
        suspicious_value = "browser"
        result = safety_filter._sanitize_string_argument(arg_name, suspicious_value)
        assert result == "[BLOCKED_SUSPICIOUS]"


def test_sanitize_string_argument_with_edge_cases(safety_filter):
    """Test _sanitize_string_argument with edge cases."""
    # Test with None value
    result = safety_filter._sanitize_string_argument("test_arg", None)
    assert result is None

    # Test with empty string
    result = safety_filter._sanitize_string_argument("test_arg", "")
    assert result == ""

    # Test with whitespace only
    result = safety_filter._sanitize_string_argument("test_arg", "   ")
    assert result == "   "


def test_should_skip_tool_call_with_dict_arguments(safety_filter):
    """Test should_skip_tool_call with dictionary arguments."""
    # Test with nested dictionary that contains dangerous content
    nested_args = {
        "config": {
            "url": "http://malicious.com",
            "safe_param": "normal_value",
        }
    }

    # This should be checked because we recurse through nested structures
    result = safety_filter.should_skip_tool_call("test_tool", nested_args)
    assert not result


def test_should_skip_tool_call_with_mixed_types(safety_filter):
    """Test should_skip_tool_call with mixed argument types."""
    mixed_args = {
        "string_param": "http://evil.com",  # Should be blocked
        "int_param": 42,  # Should be ignored
        "bool_param": True,  # Should be ignored
        "list_param": [
            "safe_item",
            "https://dangerous.com",
        ],  # Should be blocked
    }

    result = safety_filter.should_skip_tool_call("test_tool", mixed_args)
    assert result  # Should be blocked due to dangerous content


# Test cases for global convenience functions
def test_is_safe_tool_call():
    """Test global is_safe_tool_call function."""
    # Safe calls
    assert is_safe_tool_call("safe_tool", {})
    assert is_safe_tool_call("tool", {"arg": "safe_value"})

    # Dangerous calls
    assert not is_safe_tool_call("tool", {"url": "https://danger.com"})
    assert not is_safe_tool_call("tool", {"command": "xdg-open file"})


def test_sanitize_tool_call():
    """Test global sanitize_tool_call function."""
    tool_name = "test_tool"
    arguments = {
        "url": "https://example.com",
        "safe_arg": "value",
        "command": "xdg-open file",
    }

    sanitized_name, sanitized_args = sanitize_tool_call(tool_name, arguments)

    assert sanitized_name == tool_name
    assert sanitized_args["url"] == "[BLOCKED_URL]"
    assert sanitized_args["safe_arg"] == "value"
    assert sanitized_args["command"] == "[BLOCKED_COMMAND]"


def test_create_safety_response():
    """Test global create_safety_response function."""
    response = create_safety_response("test_tool")

    assert "error" in response
    assert "code" in response["error"]
    assert response["error"]["code"] == -32603
    assert "message" in response["error"]
    assert "SAFETY BLOCKED" in response["error"]["message"]
    assert "test_tool" in response["error"]["message"]


# Integration tests for safety functionality
@pytest.fixture
def safety_filter_integration():
    """Fixture for safety integration tests."""
    return SafetyFilter()


def test_complex_argument_sanitization(safety_filter_integration):
    """Test complex argument sanitization scenarios."""
    complex_args = {
        "config": {
            "api_url": "https://api.example.com",
            "dangerous_url": "http://malicious.org",
            "commands": ["echo hello", "xdg-open file.pdf", "ls -la"],
        },
        "nested": {"deep": {"url": "https://evil.com", "safe": "value"}},
        "list": [
            "safe_item",
            {"url": "http://dangerous.net"},
            "another_safe_item",
        ],
    }

    result = safety_filter_integration.sanitize_tool_arguments(
        "test_tool", complex_args
    )

    # Check that dangerous content was sanitized
    assert result["config"]["dangerous_url"] == "[BLOCKED_URL]"
    assert result["config"]["commands"][1] == "[BLOCKED_COMMAND]"
    assert result["nested"]["deep"]["url"] == "[BLOCKED_URL]"
    assert result["list"][1]["url"] == "[BLOCKED_URL]"

    # Check that safe content was preserved (but URLs are blocked)
    assert result["config"]["api_url"] == "[BLOCKED_URL]"
    assert result["config"]["commands"][0] == "echo hello"
    assert result["config"]["commands"][2] == "ls -la"
    assert result["nested"]["deep"]["safe"] == "value"
    assert result["list"][0] == "safe_item"
    assert result["list"][2] == "another_safe_item"


def test_edge_cases(safety_filter_integration):
    """Test various edge cases."""
    # Test with very long strings
    long_string = "a" * 10000
    result = safety_filter_integration._sanitize_string_argument("test", long_string)
    assert result == long_string

    # Test with unicode characters
    unicode_string = "测试字符串"
    result = safety_filter_integration._sanitize_string_argument("test", unicode_string)
    assert result == unicode_string

    # Test with special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    result = safety_filter_integration._sanitize_string_argument("test", special_chars)
    assert result == special_chars


def test_performance_with_large_arguments(safety_filter_integration):
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
    result = safety_filter_integration.sanitize_tool_arguments("test_tool", large_args)

    # Verify the structure is preserved
    assert isinstance(result, dict)
    assert "level_0" in result


def test_real_world_scenarios(safety_filter_integration):
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

    result = safety_filter_integration.sanitize_tool_arguments("api_tool", api_config)

    assert result["base_url"] == "[BLOCKED_URL]"
    assert result["endpoints"]["dangerous"] == "[BLOCKED_URL]"
    assert result["commands"]["open"] == "[BLOCKED_COMMAND]"
    assert result["commands"]["backup"] == "tar -czf backup.tar.gz /data"
