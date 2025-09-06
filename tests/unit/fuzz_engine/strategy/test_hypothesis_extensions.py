#!/usr/bin/env python3
"""
Tests for Hypothesis Extensions

This module contains tests for the enhanced fuzzing capabilities
using Hypothesis extensions.
"""

import asyncio
import json
import pytest
from unittest.mock import patch, MagicMock

from mcp_fuzzer.fuzz_engine.strategy.hypothesis_extensions import hypothesis_extensions


class TestHypothesisExtensions:
    """Test cases for Hypothesis extensions functionality."""

    @pytest.mark.asyncio
    async def test_generate_from_json_schema_basic(self):
        """Test basic JSON schema data generation."""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "value": {"type": "integer"}
            }
        }

        results = await hypothesis_extensions.generate_from_json_schema(schema, max_examples=3)

        assert len(results) <= 3
        for result in results:
            assert isinstance(result, dict)
            if "name" in result:
                assert isinstance(result["name"], str)
            if "value" in result:
                assert isinstance(result["value"], int)

    @pytest.mark.asyncio
    async def test_generate_from_json_schema_empty(self):
        """Test generation with empty schema."""
        schema = {}
        results = await hypothesis_extensions.generate_from_json_schema(schema, max_examples=2)

        # Should handle empty schema gracefully
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_generate_realistic_user_data_without_faker(self):
        """Test realistic data generation fallback when faker is not available."""
        with patch('mcp_fuzzer.fuzz_engine.strategy.hypothesis_extensions.FAKER_AVAILABLE', False):
            results = await hypothesis_extensions.generate_realistic_user_data("email", count=3)

            assert len(results) == 3
            for result in results:
                assert isinstance(result, str)
                assert "email" in result

    @pytest.mark.asyncio
    async def test_generate_realistic_user_data_unknown_type(self):
        """Test realistic data generation with unknown data type."""
        results = await hypothesis_extensions.generate_realistic_user_data("unknown_type", count=2)

        assert len(results) == 2
        for result in results:
            assert isinstance(result, str)
            assert "unknown_type" in result

    @pytest.mark.asyncio
    async def test_create_enhanced_protocol_strategy(self):
        """Test creation of enhanced protocol strategy."""
        base_schema = {
            "type": "object",
            "properties": {"method": {"type": "string"}}
        }

        strategy = hypothesis_extensions.create_enhanced_protocol_strategy(base_schema)

        # Should return a strategy object
        assert strategy is not None

    @pytest.mark.asyncio
    async def test_fuzz_with_extensions_basic(self):
        """Test basic fuzzing with extensions."""
        schema = {
            "type": "object",
            "properties": {"test": {"type": "string"}}
        }

        results = await hypothesis_extensions.fuzz_with_extensions(
            schema, runs=2, use_realistic_data=False
        )

        assert len(results) == 2
        for result in results:
            assert "protocol_type" in result
            assert "run" in result
            assert "fuzz_data" in result
            assert "success" in result
            assert "strategy" in result

    @pytest.mark.asyncio
    async def test_fuzz_with_extensions_with_realistic_data(self):
        """Test fuzzing with realistic data generation."""
        schema = {
            "type": "object",
            "properties": {"email": {"type": "string"}}
        }

        results = await hypothesis_extensions.fuzz_with_extensions(
            schema, runs=2, use_realistic_data=True
        )

        assert len(results) == 2
        # Should complete without errors even if faker is not available

    @pytest.mark.asyncio
    async def test_fuzz_with_extensions_invalid_schema(self):
        """Test fuzzing with invalid schema."""
        invalid_schema = {"invalid": "schema"}

        results = await hypothesis_extensions.fuzz_with_extensions(
            invalid_schema, runs=1, use_realistic_data=False
        )

        # Should handle invalid schema gracefully
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_generate_batch_from_schemas(self):
        """Test batch generation from multiple schemas."""
        schemas = [
            {"type": "object", "properties": {"a": {"type": "string"}}},
            {"type": "object", "properties": {"b": {"type": "integer"}}}
        ]

        results = await hypothesis_extensions.generate_batch_from_schemas(schemas, batch_size=2)

        assert len(results) <= 4  # 2 schemas * 2 examples each
        for result in results:
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_create_mcp_message_strategy(self):
        """Test MCP message strategy creation."""
        strategy = hypothesis_extensions.create_mcp_message_strategy("request")

        assert strategy is not None

        strategy_response = hypothesis_extensions.create_mcp_message_strategy("response")
        assert strategy_response is not None

        strategy_notification = hypothesis_extensions.create_mcp_message_strategy("notification")
        assert strategy_notification is not None


class TestHypothesisExtensionsIntegration:
    """Integration tests for Hypothesis extensions."""

    @pytest.mark.asyncio
    async def test_full_fuzzing_workflow(self):
        """Test complete fuzzing workflow with extensions."""
        # Define a realistic MCP schema
        mcp_schema = {
            "type": "object",
            "properties": {
                "jsonrpc": {"type": "string", "enum": ["2.0"]},
                "id": {"type": ["integer", "string", "null"]},
                "method": {"type": "string"},
                "params": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "integer"}
                    }
                }
            },
            "required": ["jsonrpc", "method"]
        }

        # Generate data from schema
        schema_data = await hypothesis_extensions.generate_from_json_schema(
            mcp_schema, max_examples=5
        )

        # Fuzz with extensions
        fuzz_results = await hypothesis_extensions.fuzz_with_extensions(
            mcp_schema, runs=3, use_realistic_data=False
        )

        # Verify results
        assert len(fuzz_results) == 3
        for result in fuzz_results:
            assert result["strategy"] == "hypothesis_extensions"
            assert "extensions_used" in result

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in extensions."""
        # Test with None schema
        results = await hypothesis_extensions.fuzz_with_extensions(
            None, runs=1, use_realistic_data=False
        )

        assert isinstance(results, list)

        # Test with malformed schema
        malformed_schema = {"type": "invalid"}
        results = await hypothesis_extensions.fuzz_with_extensions(
            malformed_schema, runs=1, use_realistic_data=False
        )

        assert isinstance(results, list)