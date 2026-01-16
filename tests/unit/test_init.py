#!/usr/bin/env python3
"""
Unit tests for the __init__.py module.
"""

import sys
import unittest
import importlib
from unittest.mock import patch


class TestInit(unittest.TestCase):
    """Test cases for the __init__ module."""

    def test_version_check_raises_on_old_python(self):
        """Test that importing with Python < 3.10 raises RuntimeError."""
        # Clear module cache
        if "mcp_fuzzer" in sys.modules:
            del sys.modules["mcp_fuzzer"]
            # Also clear submodules
            modules_to_remove = [
                k for k in list(sys.modules.keys()) if k.startswith("mcp_fuzzer")
            ]
            for module in modules_to_remove:
                del sys.modules[module]

        with patch.object(sys, "version_info", (3, 9, 0)), patch.object(
            sys, "version", "3.9.0"
        ):
            with self.assertRaises(RuntimeError) as ctx:
                importlib.import_module("mcp_fuzzer")
        error_msg = str(ctx.exception)
        self.assertIn("Python 3.10+", error_msg)
        self.assertIn("3.9.0", error_msg)

    def test_import_succeeds_with_python_310_plus(self):
        """Test that import succeeds with Python 3.10+."""
        # This should not raise
        import mcp_fuzzer  # noqa: F401

        self.assertTrue(hasattr(mcp_fuzzer, "__version__"))
        self.assertTrue(hasattr(mcp_fuzzer, "MCPFuzzerClient"))


if __name__ == "__main__":
    unittest.main()
