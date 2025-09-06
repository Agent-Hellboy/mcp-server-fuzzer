#!/usr/bin/env python3
"""
Hypothesis Extensions for Enhanced Fuzzing

This module provides enhanced fuzzing strategies using Hypothesis extensions
to generate more realistic and comprehensive test data for MCP server fuzzing.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from hypothesis import strategies as st
from hypothesis_jsonschema import from_schema

try:
    from faker import Faker
    FAKER_AVAILABLE = True
except ImportError:
    FAKER_AVAILABLE = False
    Faker = None

from ...types import FuzzDataResult


class HypothesisExtensions:
    """Enhanced fuzzing strategies using Hypothesis extensions."""

    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self._faker = Faker() if FAKER_AVAILABLE else None

        # Mapping of data types to Faker methods
        self.faker_mappings = {
            "email": "email",
            "name": "name",
            "address": "address",
            "phone": "phone_number",
            "company": "company",
            "url": "url",
            "text": "text",
            "sentence": "sentence",
            "word": "word",
            "uuid": "uuid4",
            "date": "date",
            "datetime": "date_time",
        }

    async def generate_from_json_schema(
        self,
        schema: Dict[str, Any],
        max_examples: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Generate test data from JSON schema using hypothesis-jsonschema.

        Args:
            schema: JSON schema to generate data from
            max_examples: Maximum number of examples to generate

        Returns:
            List of generated data examples
        """
        try:
            strategy = from_schema(schema)
            examples = []

            for _ in range(max_examples):
                try:
                    # Run in thread pool to avoid asyncio issues
                    loop = asyncio.get_running_loop()
                    example = await loop.run_in_executor(None, strategy.example)
                    examples.append(example)
                except Exception as e:
                    self._logger.debug(f"Failed to generate example from schema: {e}")
                    continue

            return examples

        except Exception as e:
            self._logger.error(f"Failed to create strategy from schema: {e}")
            return []

    async def generate_realistic_user_data(
        self,
        data_type: str,
        count: int = 10
    ) -> List[Any]:
        """
        Generate realistic user data using hypothesis-faker.

        Args:
            data_type: Type of data to generate (email, name, address, etc.)
            count: Number of examples to generate

        Returns:
            List of generated realistic data
        """
        if not FAKER_AVAILABLE:
            self._logger.warning(
                "hypothesis-faker not available, falling back to basic generation"
            )
            return [f"fake_{data_type}_{i}" for i in range(count)]

        try:
            # Map common data types to faker providers
            faker_mappings = {
                "email": "email",
                "name": "name",
                "address": "address",
                "phone": "phone_number",
                "company": "company",
                "url": "url",
                "text": "text",
                "sentence": "sentence",
                "word": "word",
                "uuid": "uuid4",
                "date": "date",
                "datetime": "date_time",
            }

            if data_type not in faker_mappings:
                return [f"fake_{data_type}_{i}" for i in range(count)]

            faker_method = faker_mappings[data_type]
            examples = []

            for _ in range(count):
                try:
                    # Use Faker directly
                    example = getattr(self._faker, faker_method)()
                    examples.append(example)
                except Exception as e:
                    self._logger.debug(f"Failed to generate fake {data_type}: {e}")
                    continue

            return examples

        except Exception as e:
            self._logger.error(f"Failed to generate realistic data: {e}")
            return [f"fallback_{data_type}_{i}" for i in range(count)]

    def create_enhanced_protocol_strategy(
        self,
        base_schema: Dict[str, Any],
        realistic_fields: Optional[Dict[str, Any]] = None
    ) -> st.SearchStrategy:
        """
        Create an enhanced strategy that combines JSON schema with realistic data.

        Args:
            base_schema: Base JSON schema
            realistic_fields: Fields to enhance with realistic data

        Returns:
            Enhanced Hypothesis strategy
        """
        try:
            base_strategy = from_schema(base_schema)

            if realistic_fields and FAKER_AVAILABLE:
                # Enhance specific fields with realistic data
                enhancements = {}
                for field, data_type in realistic_fields.items():
                    # Use Faker directly for realistic data
                    if data_type in self.faker_mappings:
                        faker_method = self.faker_mappings[data_type]
                        enhancements[field] = st.just(
                            getattr(self._faker, faker_method)()
                        )
                    else:
                        enhancements[field] = st.just(f"fake_{data_type}")

                return base_strategy.flatmap(
                    lambda base_data: st.builds(
                        lambda **kwargs: {**base_data, **kwargs},
                        **enhancements
                    )
                )

            return base_strategy

        except Exception as e:
            self._logger.error(f"Failed to create enhanced strategy: {e}")
            return st.just({})

    async def generate_batch_from_schemas(
        self,
        schemas: List[Dict[str, Any]],
        batch_size: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate a batch of data from multiple schemas.

        Args:
            schemas: List of JSON schemas
            batch_size: Number of items per schema

        Returns:
            List of generated data from all schemas
        """
        all_examples = []

        for schema in schemas:
            examples = await self.generate_from_json_schema(schema, batch_size)
            all_examples.extend(examples)

        return all_examples

    def create_mcp_message_strategy(
        self,
        message_type: str = "request"
    ) -> st.SearchStrategy:
        """
        Create a strategy for generating MCP protocol messages.

        Args:
            message_type: Type of MCP message (request, response, notification)

        Returns:
            Strategy for generating MCP messages
        """
        base_schema = {
            "type": "object",
            "properties": {
                "jsonrpc": {"type": "string", "enum": ["2.0"]},
                "id": {"type": ["string", "integer", "null"]},
                "method": {"type": "string"},
                "params": {"type": "object"},
            },
            "required": ["jsonrpc", "method"]
        }

        if message_type == "response":
            base_schema["properties"]["result"] = {"type": "object"}
            base_schema["properties"]["error"] = {"type": "object"}
        elif message_type == "notification":
            # Notifications don't have id
            if "id" in base_schema["properties"]:
                del base_schema["properties"]["id"]
            if "id" in base_schema.get("required", []):
                base_schema["required"].remove("id")

        return from_schema(base_schema)

    async def fuzz_with_extensions(
        self,
        schema: Dict[str, Any],
        runs: int = 10,
        use_realistic_data: bool = True
    ) -> List[FuzzDataResult]:
        """
        Perform fuzzing using Hypothesis extensions.

        Args:
            schema: JSON schema to fuzz
            runs: Number of fuzzing runs
            use_realistic_data: Whether to use realistic data generation

        Returns:
            List of fuzzing results
        """
        results = []

        try:
            if use_realistic_data and FAKER_AVAILABLE:
                # Use enhanced strategy with realistic data
                strategy = self.create_enhanced_protocol_strategy(
                    schema,
                    realistic_fields={
                        "name": "name",
                        "email": "email",
                        "url": "url",
                        "description": "text"
                    }
                )
            else:
                # Use basic JSON schema strategy
                strategy = from_schema(schema)

            for run in range(runs):
                try:
                    loop = asyncio.get_running_loop()
                    example = await loop.run_in_executor(None, strategy.example)

                    result = {
                        "protocol_type": "EnhancedFuzz",
                        "run": run + 1,
                        "fuzz_data": example,
                        "success": True,
                        "strategy": "hypothesis_extensions",
                        "extensions_used": ["jsonschema"] + (
                            ["faker"] if FAKER_AVAILABLE else []
                        )
                    }

                    results.append(result)

                except Exception as e:
                    self._logger.debug(
                        f"Failed to generate example in run {run + 1}: {e}"
                    )
                    results.append({
                        "protocol_type": "EnhancedFuzz",
                        "run": run + 1,
                        "fuzz_data": None,
                        "success": False,
                        "exception": str(e),
                        "strategy": "hypothesis_extensions"
                    })

        except Exception as e:
            self._logger.error(f"Failed to create fuzzing strategy: {e}")

        return results


# Global instance for easy access
hypothesis_extensions = HypothesisExtensions()