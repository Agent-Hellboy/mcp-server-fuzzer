#!/usr/bin/env python3
"""
Alternative Fuzzing Libraries Integration

This module integrates various Python fuzzing libraries for enhanced fuzzing
capabilities including mutation-based, coverage-guided, and other testing strategies.
"""

import asyncio
import json
import logging
import random
import string
from typing import Any, Dict, List, Callable, Union

try:
    import atheris
    ATHERIS_AVAILABLE = True
except ImportError:
    ATHERIS_AVAILABLE = False
    atheris = None

try:
    from pythonfuzz.main import PythonFuzz
    PYTHONFUZZ_AVAILABLE = True
except ImportError:
    PYTHONFUZZ_AVAILABLE = False
    PythonFuzz = None

from ...types import FuzzDataResult


class AlternativeFuzzers:
    """Integration of alternative fuzzing libraries for enhanced testing."""

    def __init__(self):
        self._logger = logging.getLogger(__name__)

    async def atheris_mutation_fuzz(
        self,
        target_function: Callable,
        initial_inputs: List[bytes],
        max_iterations: int = 1000,
        timeout_seconds: int = 30
    ) -> List[FuzzDataResult]:
        """
        Use Atheris for mutation-based fuzzing.

        Args:
            target_function: Function to fuzz
            initial_inputs: Initial input corpus
            max_iterations: Maximum fuzzing iterations
            timeout_seconds: Timeout for fuzzing session

        Returns:
            List of fuzzing results
        """
        if not ATHERIS_AVAILABLE:
            self._logger.warning(
                "Atheris not available, skipping mutation-based fuzzing"
            )
            return []

        results = []

        def test_function(input_bytes: bytes) -> None:
            """Test function wrapper for Atheris."""
            try:
                # Convert bytes to string for JSON parsing
                input_str = input_bytes.decode('utf-8', errors='ignore')

                # Try to parse as JSON
                try:
                    data = json.loads(input_str)
                except json.JSONDecodeError:
                    # If not JSON, treat as raw string
                    data = input_str

                # Call target function
                target_function(data)

                # If we reach here, input was processed successfully
                results.append({
                    "protocol_type": "AtherisMutation",
                    "fuzz_data": data,
                    "success": True,
                    "strategy": "mutation_based",
                    "library": "atheris"
                })

            except Exception as e:
                # Input caused an exception - this might be interesting
                results.append({
                    "protocol_type": "AtherisMutation",
                    "fuzz_data": input_bytes,
                    "success": False,
                    "exception": str(e),
                    "strategy": "mutation_based",
                    "library": "atheris"
                })

        try:
            # Set up Atheris fuzzing
            atheris.Setup(initial_inputs, test_function)

            # Run fuzzing with timeout
            loop = asyncio.get_running_loop()

            def run_fuzzing():
                try:
                    atheris.Fuzz(max_iterations=max_iterations)
                except Exception as e:
                    self._logger.debug(f"Atheris fuzzing completed with: {e}")

            await asyncio.wait_for(
                loop.run_in_executor(None, run_fuzzing),
                timeout=timeout_seconds
            )

        except asyncio.TimeoutError:
            self._logger.info("Atheris fuzzing timed out")
        except Exception as e:
            self._logger.error(f"Atheris fuzzing failed: {e}")

        return results

    async def pythonfuzz_coverage_fuzz(
        self,
        target_function: Callable,
        initial_corpus: List[bytes] = None,
        max_runs: int = 100
    ) -> List[FuzzDataResult]:
        """
        Use PythonFuzz for coverage-guided fuzzing.

        Args:
            target_function: Function to fuzz
            initial_corpus: Initial input corpus
            max_runs: Maximum number of fuzzing runs

        Returns:
            List of fuzzing results
        """
        if not PYTHONFUZZ_AVAILABLE:
            self._logger.warning(
                "PythonFuzz not available, skipping coverage-guided fuzzing"
            )
            return []

        if initial_corpus is None:
            initial_corpus = [b"{}", b'{"test": "data"}', b"[1, 2, 3]"]

        results = []

        def fuzz_target(input_data: bytes) -> None:
            """Fuzz target wrapper for PythonFuzz."""
            try:
                input_str = input_data.decode('utf-8', errors='ignore')

                try:
                    data = json.loads(input_str)
                except json.JSONDecodeError:
                    data = input_str

                target_function(data)

                results.append({
                    "protocol_type": "PythonFuzzCoverage",
                    "fuzz_data": data,
                    "success": True,
                    "strategy": "coverage_guided",
                    "library": "pythonfuzz"
                })

            except Exception as e:
                results.append({
                    "protocol_type": "PythonFuzzCoverage",
                    "fuzz_data": input_data,
                    "success": False,
                    "exception": str(e),
                    "strategy": "coverage_guided",
                    "library": "pythonfuzz"
                })

        try:
            # Create PythonFuzz instance
            fuzzer = PythonFuzz(target_function=fuzz_target, corpus=initial_corpus)

            # Run fuzzing
            loop = asyncio.get_running_loop()

            def run_pythonfuzz():
                for _ in range(max_runs):
                    try:
                        fuzzer.fuzz()
                    except Exception as e:
                        self._logger.debug(f"PythonFuzz iteration failed: {e}")
                        break

            await loop.run_in_executor(None, run_pythonfuzz)

        except Exception as e:
            self._logger.error(f"PythonFuzz fuzzing failed: {e}")

        return results

    def generate_random_mutations(
        self,
        base_input: Union[str, Dict, List],
        num_mutations: int = 10
    ) -> List[Any]:
        """
        Generate random mutations of input data for fuzzing.

        Args:
            base_input: Base input to mutate
            num_mutations: Number of mutations to generate

        Returns:
            List of mutated inputs
        """
        mutations = []

        for _ in range(num_mutations):
            if isinstance(base_input, str):
                mutation = self._mutate_string(base_input)
            elif isinstance(base_input, dict):
                mutation = self._mutate_dict(base_input.copy())
            elif isinstance(base_input, list):
                mutation = self._mutate_list(base_input.copy())
            else:
                # Convert to string and mutate
                mutation = self._mutate_string(str(base_input))

            mutations.append(mutation)

        return mutations

    def _mutate_string(self, s: str) -> str:
        """Apply random mutations to a string."""
        mutations = [
            self._insert_random_chars,
            self._delete_random_chars,
            self._replace_random_chars,
            self._duplicate_substring,
            self._swap_chars,
        ]

        mutation_func = random.choice(mutations)
        return mutation_func(s)

    def _mutate_dict(self, d: Dict) -> Dict:
        """Apply random mutations to a dictionary."""
        mutations = [
            self._add_random_key,
            self._remove_random_key,
            self._mutate_dict_value,
            self._swap_dict_keys,
        ]

        mutation_func = random.choice(mutations)
        return mutation_func(d)

    def _mutate_list(self, lst: List) -> List:
        """Apply random mutations to a list."""
        mutations = [
            self._add_list_element,
            self._remove_list_element,
            self._mutate_list_element,
            self._shuffle_list,
        ]

        mutation_func = random.choice(mutations)
        return mutation_func(lst)

    # String mutation helpers
    def _insert_random_chars(self, s: str) -> str:
        if not s:
            return "".join(random.choices(string.printable, k=5))

        pos = random.randint(0, len(s))
        chars = "".join(random.choices(string.printable, k=random.randint(1, 5)))
        return s[:pos] + chars + s[pos:]

    def _delete_random_chars(self, s: str) -> str:
        if len(s) <= 1:
            return s

        start = random.randint(0, len(s) - 1)
        end = random.randint(start + 1, min(start + 5, len(s)))
        return s[:start] + s[end:]

    def _replace_random_chars(self, s: str) -> str:
        if not s:
            return s

        pos = random.randint(0, len(s) - 1)
        replacement = random.choice(string.printable)
        return s[:pos] + replacement + s[pos + 1:]

    def _duplicate_substring(self, s: str) -> str:
        if len(s) <= 1:
            return s

        start = random.randint(0, len(s) - 1)
        end = random.randint(start + 1, len(s))
        substring = s[start:end]
        pos = random.randint(0, len(s))
        return s[:pos] + substring + s[pos:]

    def _swap_chars(self, s: str) -> str:
        if len(s) <= 1:
            return s

        i = random.randint(0, len(s) - 1)
        j = random.randint(0, len(s) - 1)
        chars = list(s)
        chars[i], chars[j] = chars[j], chars[i]
        return "".join(chars)

    # Dict mutation helpers
    def _add_random_key(self, d: Dict) -> Dict:
        key = f"key_{random.randint(0, 100)}"
        value = random.choice([
            random.randint(0, 100), "string", [1, 2, 3], {"nested": "value"}
        ])
        d[key] = value
        return d

    def _remove_random_key(self, d: Dict) -> Dict:
        if not d:
            return d

        key = random.choice(list(d.keys()))
        del d[key]
        return d

    def _mutate_dict_value(self, d: Dict) -> Dict:
        if not d:
            return d

        key = random.choice(list(d.keys()))
        if isinstance(d[key], str):
            d[key] = self._mutate_string(d[key])
        elif isinstance(d[key], int):
            d[key] = d[key] + random.randint(-10, 10)
        elif isinstance(d[key], list):
            d[key] = self._mutate_list(d[key])
        elif isinstance(d[key], dict):
            d[key] = self._mutate_dict(d[key])
        return d

    def _swap_dict_keys(self, d: Dict) -> Dict:
        if len(d) <= 1:
            return d

        keys = list(d.keys())
        i, j = random.sample(range(len(keys)), 2)
        keys[i], keys[j] = keys[j], keys[i]
        return {k: d[k] for k in keys}

    # List mutation helpers
    def _add_list_element(self, lst: List) -> List:
        element = random.choice([
            random.randint(0, 100), "string", [1, 2], {"key": "value"}
        ])
        pos = random.randint(0, len(lst))
        lst.insert(pos, element)
        return lst

    def _remove_list_element(self, lst: List) -> List:
        if not lst:
            return lst

        pos = random.randint(0, len(lst) - 1)
        del lst[pos]
        return lst

    def _mutate_list_element(self, lst: List) -> List:
        if not lst:
            return lst

        pos = random.randint(0, len(lst) - 1)
        if isinstance(lst[pos], str):
            lst[pos] = self._mutate_string(lst[pos])
        elif isinstance(lst[pos], int):
            lst[pos] = lst[pos] + random.randint(-10, 10)
        elif isinstance(lst[pos], list):
            lst[pos] = self._mutate_list(lst[pos])
        elif isinstance(lst[pos], dict):
            lst[pos] = self._mutate_dict(lst[pos])
        return lst

    def _shuffle_list(self, lst: List) -> List:
        random.shuffle(lst)
        return lst

    async def mutation_based_fuzz(
        self,
        base_inputs: List[Union[str, Dict, List]],
        target_function: Callable,
        num_mutations_per_input: int = 10
    ) -> List[FuzzDataResult]:
        """
        Perform mutation-based fuzzing using custom mutation strategies.

        Args:
            base_inputs: Base inputs to mutate
            target_function: Function to test with mutated inputs
            num_mutations_per_input: Number of mutations per base input

        Returns:
            List of fuzzing results
        """
        results = []

        for base_input in base_inputs:
            mutations = self.generate_random_mutations(
                base_input, num_mutations_per_input
            )

            for mutation in mutations:
                try:
                    # Test the mutated input
                    target_function(mutation)

                    results.append({
                        "protocol_type": "CustomMutation",
                        "fuzz_data": mutation,
                        "success": True,
                        "strategy": "mutation_based",
                        "library": "custom",
                        "base_input": base_input
                    })

                except Exception as e:
                    results.append({
                        "protocol_type": "CustomMutation",
                        "fuzz_data": mutation,
                        "success": False,
                        "exception": str(e),
                        "strategy": "mutation_based",
                        "library": "custom",
                        "base_input": base_input
                    })

        return results


# Global instance for easy access
alternative_fuzzers = AlternativeFuzzers()