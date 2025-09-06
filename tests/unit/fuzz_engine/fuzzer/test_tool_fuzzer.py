#!/usr/bin/env python3
"""
Unit tests for ToolFuzzer
"""

import logging
import unittest
import pytest
from unittest.mock import MagicMock, call, patch, AsyncMock
from mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer import ToolFuzzer

pytestmark = [pytest.mark.unit, pytest.mark.fuzz_engine, pytest.mark.fuzzer]


class TestToolFuzzer(unittest.TestCase):
    """Test cases for ToolFuzzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.fuzzer = ToolFuzzer()

    @pytest.mark.asyncio
    async def test_init(self):
        """Test ToolFuzzer initialization."""
        self.assertIsNotNone(self.fuzzer.strategies)

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    async def test_fuzz_tool_success(self, mock_logging):
        """Test fuzzing of a tool with enhanced safety."""
        tool = {
            "name": "test_tool",
            "inputSchema": {
                "properties": {
                    "name": {"type": "string"},
                    "count": {"type": "integer"},
                }
            },
        }

        results = await self.fuzzer.fuzz_tool(tool, runs=3)

        self.assertEqual(len(results), 3)

        for i, result in enumerate(results):
            self.assertEqual(result["tool_name"], "test_tool")
            self.assertEqual(result["run"], i + 1)
            # Enhanced safety may block dangerous content, which is correct behavior
            # We verify that fuzzing occurred and produced valid structure
            self.assertIn("success", result)
            self.assertIn("args", result)
            self.assertIsInstance(result["args"], dict)

            # Check that args has expected structure
            args = result["args"]
            self.assertIn("name", args)
            self.assertIn("count", args)
            self.assertIsInstance(args["name"], str)
            # count can be various types due to aggressive fuzzing
            self.assertIsInstance(args["count"], (int, float, type(None)))

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    async def test_fuzz_tool_exception_handling(self, mock_logging):
        """Test exception handling during tool fuzzing."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        # Mock the strategy to raise an exception
        with patch.object(
            self.fuzzer.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
        ) as mock_fuzz:
            mock_fuzz.side_effect = Exception("Test exception")

            results = await self.fuzzer.fuzz_tool(tool, runs=2)

            self.assertEqual(len(results), 2)

            for result in results:
                self.assertEqual(result["tool_name"], "test_tool")
                self.assertFalse(result["success"])
                self.assertIn("exception", result)
                self.assertEqual(result["exception"], "Test exception")

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    async def test_fuzz_tools(self, mock_logging):
        """Test fuzzing multiple tools."""
        tools = [
            {
                "name": "tool1",
                "inputSchema": {"properties": {"param1": {"type": "string"}}},
            },
            {
                "name": "tool2",
                "inputSchema": {"properties": {"param2": {"type": "integer"}}},
            },
        ]

        results = await self.fuzzer.fuzz_tools(tools, runs_per_tool=2)

        # Check that all tools are present
        self.assertIn("tool1", results)
        self.assertIn("tool2", results)

        # Each tool should have 2 runs
        self.assertEqual(len(results["tool1"]), 2)
        self.assertEqual(len(results["tool2"]), 2)

        # Check that at least some runs were successful
        for tool_name in ["tool1", "tool2"]:
            successful_runs = [r for r in results[tool_name] if r.get("success", False)]
            self.assertGreater(len(successful_runs), 0)

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    async def test_fuzz_tools_with_exception(self, mock_logging):
        """Test fuzzing tools with exception handling."""
        tools = [
            {
                "name": "tool1",
                "inputSchema": {"properties": {"param1": {"type": "string"}}},
            },
            {
                "name": "tool2",
                "inputSchema": {"properties": {"param2": {"type": "integer"}}},
            },
        ]

        # Mock one of the fuzzer methods to raise an exception
        with patch.object(
            self.fuzzer, "fuzz_tool", new_callable=AsyncMock
        ) as mock_fuzz:

            async def side_effect(tool, runs, phase="aggressive"):
                if tool["name"] == "tool1":
                    raise Exception("Test exception")
                else:
                    return [
                        {
                            "tool_name": tool["name"],
                            "run": 1,
                            "args": {"param2": 42},
                            "success": True,
                        }
                    ]

            mock_fuzz.side_effect = side_effect

            results = await self.fuzzer.fuzz_tools(tools, runs_per_tool=1)

            # Should still return results for all tools
            self.assertIn("tool1", results)
            self.assertIn("tool2", results)

            # tool1 should have error
            self.assertIn("error", results["tool1"][0])

            # tool2 should have proper result structure
            self.assertIn("success", results["tool2"][0])

    @pytest.mark.asyncio
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    @patch(
        "mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.is_safe_tool_call", return_value=True
    )
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.sanitize_tool_call")
    async def test_fuzz_tool_complex_schema(
        self, mock_sanitize, mock_is_safe, mock_logging
    ):
        """Test fuzzing a tool with complex schema."""
        tool = {
            "name": "complex_tool",
            "inputSchema": {
                "properties": {
                    "strings": {"type": "array", "items": {"type": "string"}},
                    "numbers": {"type": "array", "items": {"type": "number"}},
                    "metadata": {"type": "object"},
                    "enabled": {"type": "boolean"},
                }
            },
        }

        # Mock the sanitize_tool_call function to return predictable values
        mock_sanitize.return_value = (
            "complex_tool",
            {
                "strings": ["test1", "test2"],
                "numbers": [1, 2, 3],
                "metadata": {"key": "value"},
                "enabled": True,
            },
        )

        # Mock the strategy to return a simple dict
        with patch.object(
            self.fuzzer.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
        ) as mock_fuzz:
            mock_fuzz.return_value = {
                "strings": ["test1", "test2"],
                "numbers": [1, 2, 3],
                "metadata": {"key": "value"},
                "enabled": True,
            }

            results = await self.fuzzer.fuzz_tool(tool, runs=1)

            self.assertEqual(len(results), 1)
            result = results[0]

            self.assertIn("success", result)
            args = result["args"]

            # Test BEHAVIOR: fuzzer should generate arguments based on schema
            self.assertIsInstance(args, dict, "Should return a dictionary of arguments")
            self.assertGreater(len(args), 0, "Should generate some arguments")

            # Test BEHAVIOR: should generate fields based on schema properties
            schema_properties = tool["inputSchema"]["properties"].keys()
            generated_keys = set(args.keys())

            # With our mocking, we should have all the expected keys
            self.assertEqual(set(schema_properties), generated_keys)

    @pytest.mark.asyncio
    async def test_fuzz_tool_no_schema(self):
        """Test fuzzing a tool with no schema."""
        tool = {"name": "no_schema_tool"}

        results = await self.fuzzer.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        result = results[0]

        self.assertIn("success", result)
        self.assertIsInstance(result["args"], dict)

    @pytest.mark.asyncio
    async def test_fuzz_tool_empty_schema(self):
        """Test fuzzing a tool with empty schema."""
        tool = {"name": "empty_schema_tool", "inputSchema": {}}

        results = await self.fuzzer.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results), 1)
        result = results[0]

        # Test BEHAVIOR: fuzzer should complete successfully
        self.assertIn("success", result)
        # Test BEHAVIOR: should return a dictionary (may be empty or have
        # injected fields for aggressive fuzzing)
        self.assertIsInstance(result["args"], dict)

    @pytest.mark.asyncio
    async def test_fuzz_tool_zero_runs(self):
        """Test fuzzing a tool with zero runs."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        results = await self.fuzzer.fuzz_tool(tool, runs=0)
        self.assertEqual(len(results), 0)

    @pytest.mark.asyncio
    async def test_fuzz_tool_negative_runs(self):
        """Test fuzzing a tool with negative runs."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        results = await self.fuzzer.fuzz_tool(tool, runs=-1)
        self.assertEqual(len(results), 0)

    @pytest.mark.asyncio
    async def test_fuzz_tools_zero_runs(self):
        """Test fuzzing tools with zero runs per tool."""
        tools = [
            {
                "name": "tool1",
                "inputSchema": {"properties": {"param1": {"type": "string"}}},
            }
        ]

        results = await self.fuzzer.fuzz_tools(tools, runs_per_tool=0)

        self.assertIn("tool1", results)
        self.assertEqual(len(results["tool1"]), 0)

    @pytest.mark.asyncio
    async def test_fuzz_tools_negative_runs(self):
        """Test fuzzing tools with negative runs per tool."""
        tools = [
            {
                "name": "tool1",
                "inputSchema": {"properties": {"param1": {"type": "string"}}},
            }
        ]

        results = await self.fuzzer.fuzz_tools(tools, runs_per_tool=-1)

        self.assertIn("tool1", results)
        self.assertEqual(len(results["tool1"]), 0)

    @patch(
        "mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.is_safe_tool_call", return_value=True
    )
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.sanitize_tool_call")
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.ToolStrategies")
    @pytest.mark.asyncio
    async def test_fuzz_tool_different_runs(
        self, mock_strategies_class, mock_sanitize, mock_is_safe
    ):
        """Test that different runs generate different arguments."""
        # Setup mock strategy to return controlled values
        mock_strategies = MagicMock()
        mock_strategies_class.return_value = mock_strategies

        # Make sanitizer a no-op for stable arg comparisons
        mock_sanitize.side_effect = lambda tool_name, args: (tool_name, args)

        # Configure mock to return different args for each call
        mock_strategies.fuzz_tool_arguments = AsyncMock(
            side_effect=[
                {"name": f"test_{i}", "count": i, "enabled": i % 2 == 0}
                for i in range(5)
            ]
        )

        # Reinitialize fuzzer to use our mock
        self.fuzzer = ToolFuzzer()

        tool = {
            "name": "test_tool",
            "inputSchema": {
                "properties": {
                    "name": {"type": "string"},
                    "count": {"type": "integer"},
                    "enabled": {"type": "boolean"},
                }
            },
        }

        results = await self.fuzzer.fuzz_tool(tool, runs=5)

        # Check that we get the expected number of results
        self.assertEqual(len(results), 5)

        # Verify the strategy was called the expected number of times
        self.assertEqual(mock_strategies.fuzz_tool_arguments.call_count, 5)

        # Check that all runs have proper structure
        for i, result in enumerate(results):
            self.assertIn("success", result)
            self.assertTrue(result["success"], "Expected success=True for each run")
            self.assertIn("args", result)

            # Test that we got the expected arguments from our mock
            args = result["args"]
            self.assertIsInstance(args, dict)
            self.assertEqual(args["name"], f"test_{i}")
            self.assertEqual(args["count"], i)
            self.assertEqual(args["enabled"], i % 2 == 0)

    @pytest.mark.asyncio
    async def test_fuzz_tools_empty_list(self):
        """Test fuzzing an empty list of tools."""
        results = await self.fuzzer.fuzz_tools([], runs_per_tool=1)
        self.assertEqual(results, {})

    @pytest.mark.asyncio
    async def test_fuzz_tools_none_list(self):
        """Test fuzzing None as tools list."""
        results = await self.fuzzer.fuzz_tools(None, runs_per_tool=1)
        self.assertEqual(results, {})

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    @patch(
        "mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.is_safe_tool_call",
        return_value=True,
    )
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.sanitize_tool_call")
    @pytest.mark.asyncio
    async def test_fuzz_tool_missing_name(
        self, mock_sanitize, mock_is_safe, mock_logging
    ):
        """Test fuzzing a tool with missing name."""
        # Mock the sanitize_tool_call function to return predictable values
        mock_sanitize.return_value = ("unknown", {"param1": "test_value"})

        tool = {"inputSchema": {"properties": {"param1": {"type": "string"}}}}

        # Mock the strategy to return a simple dict
        with patch.object(
            self.fuzzer.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
        ) as mock_fuzz:
            mock_fuzz.return_value = {"param1": "test_value"}

            results = await self.fuzzer.fuzz_tool(tool, runs=1)

            self.assertEqual(len(results), 1)
            result = results[0]

            # Should use "unknown" as tool name
            self.assertEqual(result["tool_name"], "unknown")
            # Verify that fuzzing occurred and tool name was set correctly
            self.assertIn("success", result)

    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.logging")
    @patch(
        "mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.is_safe_tool_call",
        return_value=True,
    )
    @patch("mcp_fuzzer.fuzz_engine.fuzzer.tool_fuzzer.sanitize_tool_call")
    @pytest.mark.asyncio
    async def test_fuzz_tool_none_name(self, mock_sanitize, mock_is_safe, mock_logging):
        """Test fuzzing a tool with None name."""
        # Mock the sanitize_tool_call function to return predictable values
        mock_sanitize.return_value = ("unknown", {"param1": "test_value"})

        tool = {
            "name": None,
            "inputSchema": {"properties": {"param1": {"type": "string"}}},
        }

        # Mock the strategy to return a simple dict
        with patch.object(
            self.fuzzer.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
        ) as mock_fuzz:
            mock_fuzz.return_value = {"param1": "test_value"}

            results = await self.fuzzer.fuzz_tool(tool, runs=1)

            self.assertEqual(len(results), 1)
            result = results[0]

            # Should use "unknown" as tool name (None is also acceptable)
            self.assertIn(result["tool_name"], ["unknown", None])
            # Verify that fuzzing occurred and tool name was handled correctly
            self.assertIn("success", result)

    @pytest.mark.asyncio
    async def test_logging_integration(self):
        """Test that logging is properly integrated."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        with patch.object(self.fuzzer, "_logger") as mock_logger:
            await self.fuzzer.fuzz_tool(tool, runs=1)
            mock_logger.info.assert_called()
            # Ensure the tool name made it into an info log
            calls = [str(c) for c in mock_logger.info.call_args_list]
            self.assertTrue(any("test_tool" in c for c in calls))

    @pytest.mark.asyncio
    async def test_strategy_integration(self):
        """Test integration with ToolStrategies."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        # Test that the fuzzer properly uses the strategy
        with patch.object(
            self.fuzzer.strategies, "fuzz_tool_arguments", new_callable=AsyncMock
        ) as mock_fuzz:
            mock_fuzz.return_value = {"name": "test_value"}

            results = await self.fuzzer.fuzz_tool(tool, runs=1)

            mock_fuzz.assert_called_with(tool, phase="aggressive")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["args"], {"name": "test_value"})

    @pytest.mark.asyncio
    async def test_tool_argument_validation(self):
        """Test that generated tool arguments are valid."""
        tools = [
            {
                "name": "string_tool",
                "inputSchema": {"properties": {"name": {"type": "string"}}},
            },
            {
                "name": "integer_tool",
                "inputSchema": {"properties": {"count": {"type": "integer"}}},
            },
            {
                "name": "boolean_tool",
                "inputSchema": {"properties": {"enabled": {"type": "boolean"}}},
            },
            {
                "name": "array_tool",
                "inputSchema": {
                    "properties": {
                        "items": {"type": "array", "items": {"type": "string"}}
                    }
                },
            },
        ]

        for tool in tools:
            results = await self.fuzzer.fuzz_tool(tool, runs=1)

            if results:
                result = results[0]
                if result.get("success", False):
                    args = result["args"]

                    # Basic validation
                    self.assertIsInstance(args, dict)

                    # Check that all expected arguments are present
                    for prop_name in tool["inputSchema"]["properties"]:
                        self.assertIn(prop_name, args)

    @pytest.mark.asyncio
    async def test_fuzzer_isolation(self):
        """Test that fuzzer instances are isolated."""
        fuzzer1 = ToolFuzzer()
        fuzzer2 = ToolFuzzer()

        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        # Both fuzzers should work independently
        results1 = await fuzzer1.fuzz_tool(tool, runs=1)
        results2 = await fuzzer2.fuzz_tool(tool, runs=1)

        self.assertEqual(len(results1), 1)
        self.assertEqual(len(results2), 1)
        self.assertIn("success", results1[0])
        self.assertIn("success", results2[0])
    @pytest.mark.asyncio
    async def test_fuzz_tool_both_phases(self):
        """Test fuzzing a tool in both realistic and aggressive phases."""
        tool = {
            "name": "test_tool",
            "inputSchema": {"properties": {"name": {"type": "string"}}},
        }

        results = await self.fuzzer.fuzz_tool_both_phases(tool, runs_per_phase=2)

        # Should have results for both phases
        self.assertIn("realistic", results)
        self.assertIn("aggressive", results)

        # Each phase should have 2 runs
        self.assertEqual(len(results["realistic"]), 2)
        self.assertEqual(len(results["aggressive"]), 2)

        # Check structure of results
        for phase_results in [results["realistic"], results["aggressive"]]:
            for result in phase_results:
                self.assertIn("success", result)
                self.assertIn("args", result)
                self.assertIsInstance(result["args"], dict)

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test shutdown method."""
        # Mock the executor shutdown
        with patch.object(
            self.fuzzer.executor, "shutdown", new_callable=AsyncMock
        ) as mock_shutdown:
            await self.fuzzer.shutdown()
            mock_shutdown.assert_called_once()


if __name__ == "__main__":
    unittest.main()
