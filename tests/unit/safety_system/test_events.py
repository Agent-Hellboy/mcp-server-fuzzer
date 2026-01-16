#!/usr/bin/env python3
"""Tests for safety system event logging."""

from unittest.mock import MagicMock

import pytest

from mcp_fuzzer.safety_system.detection import DangerDetector, DangerMatch, DangerType
from mcp_fuzzer.safety_system.reporting.events import (
    BlockedOperation,
    DangerousArgument,
    SafetyEventLogger,
    _truncate,
)


@pytest.fixture
def mock_detector():
    """Create a mock DangerDetector."""
    detector = MagicMock(spec=DangerDetector)
    detector.iter_matches = MagicMock(return_value=[])
    return detector


@pytest.fixture
def event_logger(mock_detector):
    """Create a SafetyEventLogger instance."""
    return SafetyEventLogger(mock_detector)


class TestSafetyEventLogger:
    """Test cases for SafetyEventLogger."""

    def test_init(self, mock_detector):
        """Test SafetyEventLogger initialization."""
        logger = SafetyEventLogger(mock_detector)
        assert logger._detector is mock_detector

    def test_build_blocked_operation_simple(self, event_logger):
        """Test build_blocked_operation with simple arguments."""
        operation = event_logger.build_blocked_operation(
            "test_tool", {"arg1": "value1", "arg2": 42}, "Test reason"
        )
        assert isinstance(operation, BlockedOperation)
        assert operation.tool_name == "test_tool"
        assert operation.reason == "Test reason"
        assert operation.arguments == {"arg1": "value1", "arg2": 42}
        assert operation.dangerous_content == []

    def test_build_blocked_operation_with_none_arguments(self, event_logger):
        """Test build_blocked_operation with None arguments."""
        operation = event_logger.build_blocked_operation(
            "test_tool", None, "Test reason"
        )
        assert operation.arguments == {}
        assert operation.dangerous_content == []

    def test_summarize_value_string(self, event_logger):
        """Test _summarize_value with string value."""
        summary, dangerous = event_logger._summarize_value("key", "test_value")
        assert summary == "test_value"
        assert dangerous == []

    def test_summarize_value_long_string(self, event_logger):
        """Test _summarize_value truncates long strings."""
        long_string = "a" * 150
        summary, dangerous = event_logger._summarize_value("key", long_string)
        assert len(summary) == 103  # 100 chars + "..."
        assert summary.endswith("...")

    def test_summarize_value_list(self, event_logger):
        """Test _summarize_value with list value."""
        items = ["item1", "item2", "item3"]
        summary, dangerous = event_logger._summarize_value("key", items)
        assert summary == items
        assert dangerous == []

    def test_summarize_value_long_list(self, event_logger):
        """Test _summarize_list with more than 10 items."""
        items = [f"item{i}" for i in range(15)]
        summary, dangerous = event_logger._summarize_value("key", items)
        assert isinstance(summary, str)
        assert "[15 items]" in summary
        assert dangerous == []

    def test_summarize_value_dict(self, event_logger):
        """Test _summarize_value with dict value."""
        nested_dict = {"nested_key": "nested_value", "nested_num": 123}
        summary, dangerous = event_logger._summarize_value("key", nested_dict)
        assert isinstance(summary, dict)
        assert summary == nested_dict
        assert dangerous == []

    def test_summarize_value_other_type(self, event_logger):
        """Test _summarize_value with non-string/list/dict value."""
        summary, dangerous = event_logger._summarize_value("key", 42)
        assert summary == 42
        assert dangerous == []

    def test_summarize_list_with_string_items(self, event_logger, mock_detector):
        """Test _summarize_list detects dangerous content in string items."""
        match = DangerMatch(
            danger_type=DangerType.URL,
            pattern="http://",
            preview="http://example.com",
        )
        # Mock iter_matches to return match only for the URL item
        def iter_matches_side_effect(value, types):
            if "http://" in value:
                return [match]
            return []
        mock_detector.iter_matches.side_effect = iter_matches_side_effect

        items = ["safe", "http://example.com", "also_safe"]
        summary, dangerous = event_logger._summarize_list("key", items)
        assert len(dangerous) == 1
        assert isinstance(dangerous[0], DangerousArgument)
        assert dangerous[0].key == "key[1]"
        assert dangerous[0].match == match

    def test_summarize_list_with_dict_items(self, event_logger):
        """Test _summarize_list processes dict items."""
        items = [{"nested": "value"}, {"another": "item"}]
        summary, dangerous = event_logger._summarize_list("key", items)
        assert isinstance(summary, list)
        assert dangerous == []

    def test_summarize_list_limits_to_five_items(self, event_logger, mock_detector):
        """Test _summarize_list only checks first 5 items for dangerous content."""
        match = DangerMatch(
            danger_type=DangerType.COMMAND,
            pattern="rm -rf",
            preview="rm -rf",
        )
        # Mock iter_matches to return match only for items containing "rm -rf"
        def iter_matches_side_effect(value, types):
            if "rm -rf" in value:
                return [match]
            return []
        mock_detector.iter_matches.side_effect = iter_matches_side_effect

        items = [f"item{i}" for i in range(10)]
        items[0] = "rm -rf /"
        items[7] = "rm -rf /"  # This should not be checked (only first 5 are checked)
        summary, dangerous = event_logger._summarize_list("key", items)
        # Only first 5 items checked, so only one match (at index 0)
        assert len(dangerous) == 1
        assert dangerous[0].key == "key[0]"

    def test_dangerous_matches_yields_arguments(self, event_logger, mock_detector):
        """Test _dangerous_matches yields DangerousArgument objects."""
        match1 = DangerMatch(
            danger_type=DangerType.URL,
            pattern="http://",
            preview="http://example.com",
        )
        match2 = DangerMatch(
            danger_type=DangerType.COMMAND,
            pattern="rm -rf",
            preview="rm -rf",
        )
        mock_detector.iter_matches.return_value = [match1, match2]

        matches = list(event_logger._dangerous_matches("test_key", "test_value"))
        assert len(matches) == 2
        assert all(isinstance(m, DangerousArgument) for m in matches)
        assert matches[0].key == "test_key"
        assert matches[0].match == match1
        assert matches[1].key == "test_key"
        assert matches[1].match == match2

    def test_summarize_arguments_nested_structure(self, event_logger):
        """Test _summarize_arguments handles nested structures."""
        arguments = {
            "simple": "value",
            "nested": {"inner": "data", "list": [1, 2, 3]},
            "list_of_dicts": [{"a": 1}, {"b": 2}],
        }
        safe_args, dangerous = event_logger._summarize_arguments(arguments)
        assert safe_args == arguments
        assert dangerous == []

    def test_build_blocked_operation_with_dangerous_content(
        self, event_logger, mock_detector
    ):
        """Test build_blocked_operation detects dangerous content."""
        match = DangerMatch(
            danger_type=DangerType.URL,
            pattern="http://",
            preview="http://malicious.com",
        )
        mock_detector.iter_matches.return_value = [match]

        operation = event_logger.build_blocked_operation(
            "test_tool", {"url": "http://malicious.com"}, "Dangerous URL"
        )
        assert len(operation.dangerous_content) == 1
        assert operation.dangerous_content[0].key == "url"
        assert operation.dangerous_content[0].match == match


class TestTruncate:
    """Test cases for _truncate helper function."""

    def test_truncate_short_string(self):
        """Test _truncate with short string."""
        result = _truncate("short")
        assert result == "short"

    def test_truncate_long_string(self):
        """Test _truncate truncates long strings."""
        long_string = "a" * 150
        result = _truncate(long_string)
        assert len(result) == 103
        assert result.endswith("...")
        assert result.startswith("a" * 100)

    def test_truncate_exact_limit(self):
        """Test _truncate with string at exact limit."""
        exact_string = "a" * 100
        result = _truncate(exact_string)
        assert result == exact_string

    def test_truncate_custom_limit(self):
        """Test _truncate with custom limit."""
        long_string = "a" * 50
        result = _truncate(long_string, limit=30)
        assert len(result) == 33
        assert result.endswith("...")
