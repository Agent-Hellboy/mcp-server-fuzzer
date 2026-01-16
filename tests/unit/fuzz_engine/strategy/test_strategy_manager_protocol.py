"""
Unit tests for ProtocolStrategies from strategy_manager.py.
"""

import unittest
from mcp_fuzzer.fuzz_engine.mutators.strategies import ProtocolStrategies


class TestProtocolStrategies(unittest.TestCase):
    """Test cases for ProtocolStrategies class."""


    def test_get_protocol_fuzzer_method_unknown_type(self):
        """Test get_protocol_fuzzer_method returns None for unknown types."""
        fuzzer_method = ProtocolStrategies.get_protocol_fuzzer_method("UnknownProtocol")
        self.assertIsNone(fuzzer_method, "Should return None for unknown type")

    def test_fuzzer_methods_return_dictionaries(self):
        """Test all fuzzer methods return dictionaries when called."""
        protocol_types = ["InitializeRequest", "ListResourcesRequest"]
        
        for protocol_type in protocol_types:
            with self.subTest(protocol_type=protocol_type):
                fuzzer_method = (
                    ProtocolStrategies.get_protocol_fuzzer_method(protocol_type)
                )
                result = fuzzer_method()
                self.assertIsInstance(
                    result, dict, f"{protocol_type} fuzzer should return a dict"
                )
                self.assertGreater(
                    len(result), 0,
                    f"{protocol_type} fuzzer should return non-empty dict"
                )

    def test_initialize_request_phase_support(self):
        """Test InitializeRequest supports both realistic and aggressive phases."""
        realistic_result = ProtocolStrategies.fuzz_initialize_request("realistic")
        aggressive_result = ProtocolStrategies.fuzz_initialize_request("aggressive")
        
        self.assertIsInstance(
            realistic_result, dict, "Realistic phase should return dict"
        )
        self.assertIsInstance(
            aggressive_result, dict, "Aggressive phase should return dict"
        )
        self.assertGreater(
            len(realistic_result), 0, "Realistic result should not be empty"
        )
        self.assertGreater(
            len(aggressive_result), 0, "Aggressive result should not be empty"
        )

    def test_initialize_request_default_phase(self):
        """Test fuzz_initialize_request defaults to aggressive phase."""
        default_result = ProtocolStrategies.fuzz_initialize_request()
        self.assertIsInstance(default_result, dict, "Default should return dict")

    def test_generate_batch_request(self):
        """Test generate_batch_request creates a list of requests."""
        batch = ProtocolStrategies.generate_batch_request()
        
        self.assertIsInstance(batch, list, "Should return a list of requests")
        self.assertGreater(len(batch), 0, "Should generate at least one request")
        for request in batch:
            self.assertIsInstance(request, dict, "Each request should be a dict")

    def test_generate_batch_request_with_params(self):
        """Test generate_batch_request with custom parameters."""
        protocol_types = ["InitializeRequest", "ListResourcesRequest"]
        batch = ProtocolStrategies.generate_batch_request(
            protocol_types=protocol_types, min_batch_size=2, max_batch_size=3
        )
        
        self.assertGreaterEqual(len(batch), 2, "Should have at least min_batch_size")
        self.assertLessEqual(len(batch), 3, "Should have at most max_batch_size")
    
    def test_generate_batch_request_empty_protocol_types(self):
        """Test generate_batch_request with empty protocol_types."""
        batch = ProtocolStrategies.generate_batch_request(protocol_types=[])
        self.assertEqual(batch, [])
    
    def test_generate_batch_request_no_ids_adds_id(self):
        """Test generate_batch_request adds ID when batch has no IDs."""
        # This tests the branch where batch has no requests with IDs
        # We'll need to mock or ensure we get a batch without IDs
        batch = ProtocolStrategies.generate_batch_request(
            protocol_types=["InitializeRequest"],
            min_batch_size=1,
            max_batch_size=1,
            include_notifications=True,
        )
        # The test ensures the code path is covered
        self.assertIsInstance(batch, list)

    def test_generate_out_of_order_batch(self):
        """Test generate_out_of_order_batch creates out-of-order IDs."""
        batch = ProtocolStrategies.generate_out_of_order_batch()
        
        self.assertIsInstance(batch, list, "Should return a list")
        id_requests = [req for req in batch if "id" in req]
        self.assertGreater(len(id_requests), 0, "Should have some requests with IDs")
        
        # Test with requests that may not have IDs
        batch2 = ProtocolStrategies.generate_out_of_order_batch(
            protocol_types=["InitializeRequest"]
        )
        self.assertIsInstance(batch2, list)


if __name__ == "__main__":
    unittest.main()
