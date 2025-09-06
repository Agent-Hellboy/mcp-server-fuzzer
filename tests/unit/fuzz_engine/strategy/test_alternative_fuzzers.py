#!/usr/bin/env python3
"""
Tests for Alternative Fuzzing Libraries

This module contains tests for the alternative fuzzing libraries integration.
"""

import asyncio
import pytest
from unittest.mock import patch, MagicMock

from mcp_fuzzer.fuzz_engine.strategy.alternative_fuzzers import alternative_fuzzers


class TestAlternativeFuzzers:
    """Test cases for alternative fuzzing libraries."""

    def test_generate_random_mutations_string(self):
        """Test random string mutations."""
        base_string = "test_input"
        mutations = alternative_fuzzers.generate_random_mutations(base_string, num_mutations=5)

        assert len(mutations) == 5
        for mutation in mutations:
            assert isinstance(mutation, str)

    def test_generate_random_mutations_dict(self):
        """Test random dictionary mutations."""
        base_dict = {"key": "value", "number": 42}
        mutations = alternative_fuzzers.generate_random_mutations(base_dict, num_mutations=3)

        assert len(mutations) == 3
        for mutation in mutations:
            assert isinstance(mutation, dict)

    def test_generate_random_mutations_list(self):
        """Test random list mutations."""
        base_list = [1, 2, "three"]
        mutations = alternative_fuzzers.generate_random_mutations(base_list, num_mutations=4)

        assert len(mutations) == 4
        for mutation in mutations:
            assert isinstance(mutation, list)

    @pytest.mark.asyncio
    async def test_mutation_based_fuzz_success(self):
        """Test successful mutation-based fuzzing."""
        base_inputs = [{"test": "data"}]

        def target_function(data):
            return True  # Always succeeds

        results = await alternative_fuzzers.mutation_based_fuzz(
            base_inputs, target_function, num_mutations_per_input=3
        )

        assert len(results) >= 3  # At least the original + mutations
        for result in results:
            assert "protocol_type" in result
            assert "fuzz_data" in result
            assert result["success"] is True
            assert "strategy" in result

    @pytest.mark.asyncio
    async def test_mutation_based_fuzz_with_failures(self):
        """Test mutation-based fuzzing with some failures."""
        base_inputs = [{"method": "test"}]

        def target_function(data):
            if isinstance(data, dict) and data.get("method") == "malicious":
                raise ValueError("Malicious method detected")
            return True

        results = await alternative_fuzzers.mutation_based_fuzz(
            base_inputs, target_function, num_mutations_per_input=5
        )

        assert len(results) >= 1
        # Should have some successful and potentially some failed results
        successful = [r for r in results if r.get("success")]
        assert len(successful) > 0

    @pytest.mark.asyncio
    async def test_atheris_fuzz_unavailable(self):
        """Test Atheris fuzzing when library is not available."""
        # Since Atheris is not available in this environment, test the fallback
        def target_function(data):
            return True

        results = await alternative_fuzzers.atheris_mutation_fuzz(
            target_function, [b"test"], max_iterations=10
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_pythonfuzz_coverage_fuzz_unavailable(self):
        """Test PythonFuzz when library is not available."""
        # Since PythonFuzz is not available in this environment, test the fallback
        def target_function(data):
            return True

        results = await alternative_fuzzers.pythonfuzz_coverage_fuzz(
            target_function, [b"test"], max_runs=5
        )

        assert results == []

    def test_string_mutation_helpers(self):
        """Test individual string mutation helper functions."""
        test_string = "hello"

        # Test insert
        mutated = alternative_fuzzers._insert_random_chars(test_string)
        assert isinstance(mutated, str)
        assert len(mutated) >= len(test_string)

        # Test delete
        if len(test_string) > 1:
            mutated = alternative_fuzzers._delete_random_chars(test_string)
            assert isinstance(mutated, str)
            assert len(mutated) <= len(test_string)

        # Test replace
        mutated = alternative_fuzzers._replace_random_chars(test_string)
        assert isinstance(mutated, str)
        assert len(mutated) == len(test_string)

        # Test duplicate
        mutated = alternative_fuzzers._duplicate_substring(test_string)
        assert isinstance(mutated, str)
        assert len(mutated) >= len(test_string)

        # Test swap
        if len(test_string) > 1:
            mutated = alternative_fuzzers._swap_chars(test_string)
            assert isinstance(mutated, str)
            assert len(mutated) == len(test_string)

    def test_dict_mutation_helpers(self):
        """Test dictionary mutation helper functions."""
        test_dict = {"a": 1, "b": "test"}

        # Test add key
        mutated = alternative_fuzzers._add_random_key(test_dict.copy())
        assert isinstance(mutated, dict)
        assert len(mutated) >= len(test_dict)

        # Test remove key
        if test_dict:
            mutated = alternative_fuzzers._remove_random_key(test_dict.copy())
            assert isinstance(mutated, dict)
            assert len(mutated) <= len(test_dict)

        # Test mutate value
        mutated = alternative_fuzzers._mutate_dict_value(test_dict.copy())
        assert isinstance(mutated, dict)
        assert len(mutated) == len(test_dict)

    def test_list_mutation_helpers(self):
        """Test list mutation helper functions."""
        test_list = [1, 2, 3]

        # Test add element
        mutated = alternative_fuzzers._add_list_element(test_list.copy())
        assert isinstance(mutated, list)
        assert len(mutated) >= len(test_list)

        # Test remove element
        if test_list:
            mutated = alternative_fuzzers._remove_list_element(test_list.copy())
            assert isinstance(mutated, list)
            assert len(mutated) <= len(test_list)

        # Test mutate element
        mutated = alternative_fuzzers._mutate_list_element(test_list.copy())
        assert isinstance(mutated, list)
        assert len(mutated) == len(test_list)

        # Test shuffle
        mutated = alternative_fuzzers._shuffle_list(test_list.copy())
        assert isinstance(mutated, list)
        assert len(mutated) == len(test_list)
        assert set(mutated) == set(test_list)  # Same elements, possibly reordered


class TestAlternativeFuzzersIntegration:
    """Integration tests for alternative fuzzing libraries."""

    @pytest.mark.asyncio
    async def test_comprehensive_mutation_fuzzing(self):
        """Test comprehensive mutation-based fuzzing workflow."""
        base_inputs = [
            {"jsonrpc": "2.0", "method": "test"},
            {"jsonrpc": "2.0", "method": "initialize", "params": {}},
            "string_input",
            [1, 2, 3]
        ]

        def comprehensive_target(data):
            """Target function that checks various conditions."""
            if isinstance(data, dict):
                if data.get("method") == "forbidden":
                    raise ValueError("Forbidden method")
                if "params" in data and len(str(data["params"])) > 1000:
                    raise ValueError("Params too large")
            elif isinstance(data, str):
                if len(data) > 1000:
                    raise ValueError("String too long")
            elif isinstance(data, list):
                if len(data) > 100:
                    raise ValueError("List too long")

            return True

        results = await alternative_fuzzers.mutation_based_fuzz(
            base_inputs, comprehensive_target, num_mutations_per_input=10
        )

        assert len(results) >= len(base_inputs)  # At least original inputs

        # Check that we have both successful and potentially failed results
        successful_results = [r for r in results if r.get("success")]
        assert len(successful_results) > 0

        # Verify result structure
        for result in results:
            assert "protocol_type" in result
            assert "fuzz_data" in result
            assert "success" in result
            assert "strategy" in result
            assert result["strategy"] == "mutation_based"
            assert result["library"] == "custom"

    @pytest.mark.asyncio
    async def test_empty_base_inputs(self):
        """Test fuzzing with empty base inputs."""
        def target_function(data):
            return True

        results = await alternative_fuzzers.mutation_based_fuzz(
            [], target_function, num_mutations_per_input=5
        )

        assert results == []

    @pytest.mark.asyncio
    async def test_target_function_exceptions(self):
        """Test handling of exceptions in target function."""
        base_inputs = [{"test": "data"}]

        def failing_target(data):
            raise Exception("Test exception")

        results = await alternative_fuzzers.mutation_based_fuzz(
            base_inputs, failing_target, num_mutations_per_input=3
        )

        assert len(results) >= 1
        for result in results:
            assert result["success"] is False
            assert "exception" in result