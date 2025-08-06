#!/usr/bin/env python3
"""
Test script for the MCP Protocol Fuzzer

This script demonstrates the new modular fuzzer functionality by generating
sample fuzz cases and showing how they would be used.
"""

import json
import sys
import os

# Add the parent directory to the path so we can import mcp_fuzzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mcp_fuzzer.fuzzer.protocol_fuzzer import ProtocolFuzzer
from mcp_fuzzer.strategy.protocol_strategies import ProtocolStrategies
from mcp_fuzzer.strategy.tool_strategies import ToolStrategies


def test_protocol_fuzzer():
    """Test the protocol fuzzer by generating sample cases."""
    print("=== MCP Protocol Fuzzer Test ===")

    fuzzer = ProtocolFuzzer()
    strategies = ProtocolStrategies()

    # Test each protocol type
    protocol_types = [
        "InitializeRequest",
        "ProgressNotification",
        "CancelNotification",
        "ListResourcesRequest",
        "ReadResourceRequest",
        "SetLevelRequest",
        "GenericJSONRPCRequest",
        "CreateMessageRequest",
        "ListPromptsRequest",
        "GetPromptRequest",
        "ListRootsRequest",
        "SubscribeRequest",
        "UnsubscribeRequest",
        "CompleteRequest",
    ]

    print(f"\nTesting {len(protocol_types)} protocol types...")

    for protocol_type in protocol_types:
        print(f"\n--- {protocol_type} ---")

        try:
            # Get the fuzzer method for this protocol type
            fuzzer_method = strategies.get_protocol_fuzzer_method(protocol_type)

            if not fuzzer_method:
                print(f"  Unknown protocol type: {protocol_type}")
                continue

            # Generate a sample fuzz case
            data = fuzzer_method()

            # Print the generated data
            print("  Generated data:")
            print(json.dumps(data, indent=4))

            # Validate JSON serialization
            try:
                json_str = json.dumps(data)
                print(f"  ✓ JSON serialization successful ({len(json_str)} bytes)")
            except Exception as e:
                print(f"  ✗ JSON serialization failed: {e}")

        except Exception as e:
            print(f"  ✗ Error generating {protocol_type}: {e}")

    # Test generating all fuzz cases
    print("\n--- Generating All Fuzz Cases ---")
    try:
        all_cases = fuzzer.generate_all_protocol_fuzz_cases()
        print(f"Generated {len(all_cases)} total fuzz cases")

        # Count by type
        type_counts = {}
        for case in all_cases:
            case_type = case["type"]
            type_counts[case_type] = type_counts.get(case_type, 0) + 1

        print("\nCases by type:")
        for case_type, count in sorted(type_counts.items()):
            print(f"  {case_type}: {count} cases")

    except Exception as e:
        print(f"Error generating all cases: {e}")


def demonstrate_edge_cases():
    """Demonstrate specific edge cases that the fuzzer generates."""
    print("\n=== Edge Case Demonstration ===")

    strategies = ProtocolStrategies()

    edge_cases = [
        ("InitializeRequest - Invalid Protocol Version",
         lambda: strategies.fuzz_initialize_request()),
        ("ProgressNotification - Negative Progress",
         lambda: strategies.fuzz_progress_notification()),
        ("CancelNotification - Unknown Request ID",
         lambda: strategies.fuzz_cancel_notification()),
        ("ReadResourceRequest - Path Traversal",
         lambda: strategies.fuzz_read_resource_request()),
        ("SetLevelRequest - Invalid Log Level",
         lambda: strategies.fuzz_set_level_request()),
        ("GenericJSONRPCRequest - Missing Fields",
         lambda: strategies.fuzz_generic_jsonrpc_request()),
    ]

    for description, generator in edge_cases:
        print(f"\n--- {description} ---")
        try:
            data = generator()
            print(json.dumps(data, indent=2))
        except Exception as e:
            print(f"Error: {e}")


def test_tool_fuzzing():
    """Test the tool fuzzing functionality."""
    print("\n=== Tool Fuzzing Test ===")

    strategies = ToolStrategies()

    # Create a sample tool schema
    sample_tool = {
        "name": "test_tool",
        "inputSchema": {
            "type": "object",
            "properties": {
                "string_param": {"type": "string"},
                "integer_param": {"type": "integer"},
                "boolean_param": {"type": "boolean"},
                "array_param": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        }
    }

    print("Testing tool argument fuzzing...")
    try:
        fuzz_args = strategies.fuzz_tool_arguments(sample_tool)
        print(f"Generated tool arguments: {json.dumps(fuzz_args, indent=2)}")
        print("✓ Tool fuzzing successful")
    except Exception as e:
        print(f"✗ Tool fuzzing failed: {e}")


def test_modular_structure():
    """Test the modular structure and imports."""
    print("\n=== Modular Structure Test ===")

    try:
        # Test imports
        from mcp_fuzzer.fuzzer import ToolFuzzer, ProtocolFuzzer

        print("✓ All imports successful")

        # Test instantiation
        tool_fuzzer = ToolFuzzer()
        protocol_fuzzer = ProtocolFuzzer()

        print("✓ All classes instantiated successfully")

        # Test basic functionality
        sample_tool = {
            "name": "test_tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "string_param": {"type": "string"}
                }
            }
        }

        tool_result = tool_fuzzer.fuzz_tool(sample_tool, 1)
        protocol_result = protocol_fuzzer.fuzz_protocol_type("InitializeRequest", 1)

        print("✓ Basic fuzzing functionality working")
        print(f"  Tool fuzzer generated: {len(tool_result)} results")
        print(f"  Protocol fuzzer generated: {len(protocol_result)} results")

    except Exception as e:
        print(f"✗ Modular structure test failed: {e}")


if __name__ == "__main__":
    test_protocol_fuzzer()
    demonstrate_edge_cases()
    test_tool_fuzzing()
    test_modular_structure()

    print("\n=== Test Complete ===")
    print("The modular fuzzer is ready to use!")
    print("\nUsage examples:")
    print("  # Fuzz all protocol types")
    print("  python -m mcp_fuzzer --mode protocol --protocol http --endpoint http://localhost:8000/mcp/")
    print("\n  # Fuzz specific protocol type")
    print("  python -m mcp_fuzzer --mode protocol --protocol-type InitializeRequest --protocol http --endpoint http://localhost:8000/mcp/")
    print("\n  # Fuzz tools (original functionality)")
    print("  python -m mcp_fuzzer --mode tools --protocol http --endpoint http://localhost:8000/mcp/")
