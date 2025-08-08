#!/usr/bin/env python3
"""
Unit tests for the __main__.py module.
"""

import unittest
from unittest.mock import patch

from mcp_fuzzer.__main__ import main


class TestMain(unittest.TestCase):
    """Test cases for the main module."""

    @patch("mcp_fuzzer.__main__.run_cli")
    def test_main(self, mock_run_cli):
        """Test the main function."""
        main()
        mock_run_cli.assert_called_once()

    def test_main_import(self):
        """Test that the main module can be imported."""
        # This test ensures the module can be imported without issues
        import mcp_fuzzer.__main__

        self.assertTrue(hasattr(mcp_fuzzer.__main__, "main"))


if __name__ == "__main__":
    unittest.main()
