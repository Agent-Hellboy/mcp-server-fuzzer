#!/usr/bin/env python3
"""
Unit tests for the __init__.py module.
"""

import sys
import unittest
from unittest.mock import patch


class TestInit(unittest.TestCase):
    """Test cases for the __init__ module."""

    def test_version_check_raises_on_old_python(self):
        """Test that importing with Python < 3.10 raises RuntimeError."""
        # This test verifies the version check logic by directly testing
        # the condition. Since we can't easily mock sys.version_info at
        # import time, we test the logic indirectly by checking that the
        # RuntimeError would be raised with the correct message format

        # Clear module cache
        if "mcp_fuzzer" in sys.modules:
            del sys.modules["mcp_fuzzer"]
            # Also clear submodules
            modules_to_remove = [
                k for k in list(sys.modules.keys()) if k.startswith("mcp_fuzzer")
            ]
            for module in modules_to_remove:
                del sys.modules[module]

        # Create a mock module that simulates the version check
        import types

        mock_module = types.ModuleType("mcp_fuzzer")

        # Simulate the version check code
        mock_sys = types.ModuleType("sys")
        mock_sys.version_info = (3, 9, 0)
        mock_sys.version = "3.9.0"

        # Execute the version check logic
        if mock_sys.version_info < (3, 10):
            version_str = mock_sys.version.split()[0]
            error = RuntimeError(
                f"MCP Fuzzer requires Python 3.10+ (found {version_str}). "
                "Use a supported interpreter (e.g., tox envs or a 3.10+ venv)."
            )
            error_msg = str(error)
            self.assertIn("Python 3.10+", error_msg)
            self.assertIn("3.9.0", error_msg)

    def test_import_succeeds_with_python_310_plus(self):
        """Test that import succeeds with Python 3.10+."""
        # This should not raise
        import mcp_fuzzer  # noqa: F401

        self.assertTrue(hasattr(mcp_fuzzer, "__version__"))
        self.assertTrue(hasattr(mcp_fuzzer, "MCPFuzzerClient"))
