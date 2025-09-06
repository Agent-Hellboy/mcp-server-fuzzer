#!/usr/bin/env python3
"""
Enhanced Fuzzing Demo

This script demonstrates the enhanced fuzzing capabilities added to the MCP fuzzer,
including Hypothesis extensions and alternative fuzzing libraries.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List

from mcp_fuzzer.fuzz_engine.strategy import ProtocolStrategies
from mcp_fuzzer.fuzz_engine.strategy.hypothesis_extensions import hypothesis_extensions
from mcp_fuzzer.fuzz_engine.strategy.alternative_fuzzers import alternative_fuzzers


async def demo_hypothesis_extensions():
    """Demonstrate Hypothesis extensions for enhanced fuzzing."""
    print("🔬 Demonstrating Hypothesis Extensions")
    print("=" * 50)

    # Example JSON schema for MCP protocol messages
    mcp_schema = {
        "type": "object",
        "properties": {
            "jsonrpc": {"type": "string", "enum": ["2.0"]},
            "id": {"type": ["string", "integer", "null"]},
            "method": {"type": "string"},
            "params": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "arguments": {"type": "object"}
                }
            }
        },
        "required": ["jsonrpc", "method"]
    }

    print("📋 Generating data from JSON schema...")
    examples = await hypothesis_extensions.generate_from_json_schema(mcp_schema, max_examples=5)

    for i, example in enumerate(examples, 1):
        print(f"Example {i}: {json.dumps(example, indent=2)}")

    print("\n📧 Generating realistic user data...")
    emails = await hypothesis_extensions.generate_realistic_user_data("email", count=3)
    names = await hypothesis_extensions.generate_realistic_user_data("name", count=3)

    print(f"Generated emails: {emails}")
    print(f"Generated names: {names}")

    print("\n🎯 Enhanced fuzzing with realistic data...")
    results = await ProtocolStrategies.fuzz_with_hypothesis_extensions(
        mcp_schema, runs=3, use_realistic_data=True
    )

    for result in results:
        print(f"Fuzz result: {result['success']} - {result.get('fuzz_data', 'N/A')}")


async def demo_alternative_fuzzers():
    """Demonstrate alternative fuzzing libraries."""
    print("\n🔄 Demonstrating Alternative Fuzzing Libraries")
    print("=" * 50)

    # Sample target function to fuzz
    def target_function(data):
        """Sample function that processes JSON data."""
        if isinstance(data, dict):
            if "method" in data and len(str(data.get("method", ""))) > 100:
                raise ValueError("Method name too long")
            if "id" in data and data["id"] == "malicious":
                raise Exception("Malicious ID detected")
        return True

    # Base inputs for fuzzing
    base_inputs = [
        {"jsonrpc": "2.0", "method": "test", "id": 1},
        {"jsonrpc": "2.0", "method": "initialize", "params": {}},
        "[1, 2, 3]",
        "simple string"
    ]

    print("🧬 Custom mutation-based fuzzing...")
    mutation_results = await alternative_fuzzers.mutation_based_fuzz(
        base_inputs, target_function, num_mutations_per_input=3
    )

    successful = len([r for r in mutation_results if r.get("success")])
    failed = len([r for r in mutation_results if not r.get("success")])

    print(f"Mutation fuzzing: {successful} successful, {failed} failed")

    for result in mutation_results[:3]:  # Show first 3 results
        status = "✅" if result.get("success") else "❌"
        print(f"{status} {result.get('strategy', 'unknown')}: {result.get('fuzz_data', 'N/A')}")

    print("\n⚡ Alternative library fuzzing...")
    try:
        alt_results = await ProtocolStrategies.fuzz_with_alternative_libraries(
            base_inputs, target_function, strategy="mutation", num_mutations_per_input=2
        )

        alt_successful = len([r for r in alt_results if r.get("success")])
        alt_failed = len([r for r in alt_results if not r.get("success")])

        print(f"Alternative fuzzing: {alt_successful} successful, {alt_failed} failed")

    except Exception as e:
        print(f"Alternative fuzzing demo failed: {e}")


async def demo_combined_strategies():
    """Demonstrate combining multiple fuzzing strategies."""
    print("\n🎭 Demonstrating Combined Fuzzing Strategies")
    print("=" * 50)

    # Create a comprehensive fuzzing schema
    comprehensive_schema = {
        "type": "object",
        "properties": {
            "jsonrpc": {"type": "string", "enum": ["2.0"]},
            "method": {"type": "string"},
            "params": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "format": "email"},
                    "url": {"type": "string", "format": "uri"},
                    "timestamp": {"type": "string", "format": "date-time"}
                }
            }
        }
    }

    print("🚀 Running comprehensive fuzzing campaign...")

    # Strategy 1: Hypothesis extensions
    print("\n1️⃣ Hypothesis Extensions:")
    hypo_results = await ProtocolStrategies.fuzz_with_hypothesis_extensions(
        comprehensive_schema, runs=5, use_realistic_data=True
    )

    hypo_success = len([r for r in hypo_results if r.get("success")])
    print(f"   Results: {hypo_success}/{len(hypo_results)} successful")

    # Strategy 2: Custom mutations
    print("\n2️⃣ Custom Mutation Fuzzing:")
    base_data = [{"jsonrpc": "2.0", "method": "test"}]

    def simple_target(data):
        if isinstance(data, dict) and "method" in data:
            if len(str(data["method"])) > 50:
                raise ValueError("Method too long")
        return True

    mutation_results = await alternative_fuzzers.mutation_based_fuzz(
        base_data, simple_target, num_mutations_per_input=5
    )

    mutation_success = len([r for r in mutation_results if r.get("success")])
    print(f"   Results: {mutation_success}/{len(mutation_results)} successful")

    print("\n📊 Fuzzing Campaign Summary:")
    print(f"   Hypothesis Extensions: {hypo_success}/{len(hypo_results)} successful")
    print(f"   Custom Mutations: {mutation_success}/{len(mutation_results)} successful")
    print(f"   Total: {hypo_success + mutation_success}/{len(hypo_results) + len(mutation_results)} successful")


async def main():
    """Main demo function."""
    logging.basicConfig(level=logging.INFO)

    print("🎯 MCP Fuzzer - Enhanced Fuzzing Capabilities Demo")
    print("=" * 60)
    print("This demo showcases the new fuzzing features added to the MCP fuzzer:")
    print("• Hypothesis extensions for better data generation")
    print("• Alternative fuzzing libraries (Atheris, PythonFuzz)")
    print("• Custom mutation-based fuzzing")
    print("• Combined fuzzing strategies")
    print()

    try:
        await demo_hypothesis_extensions()
        await demo_alternative_fuzzers()
        await demo_combined_strategies()

        print("\n🎉 Demo completed successfully!")
        print("\nTo use these features in your fuzzing campaigns:")
        print("1. Import the enhanced modules:")
        print("   from mcp_fuzzer.fuzz_engine.strategy import ProtocolStrategies")
        print("2. Use the new methods:")
        print("   await ProtocolStrategies.fuzz_with_hypothesis_extensions(schema)")
        print("   await ProtocolStrategies.fuzz_with_alternative_libraries(inputs, func)")
        print("3. Check the documentation for more advanced usage patterns")

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())