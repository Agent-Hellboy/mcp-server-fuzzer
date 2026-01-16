#!/usr/bin/env python3
"""
Unit tests for the __main__.py module.
"""

import unittest
from unittest.mock import patch

import mcp_fuzzer.__main__


class TestMain(unittest.TestCase):
    """Test cases for the main module."""

    @patch.object(mcp_fuzzer.__main__, "run_cli")
    def test_main(self, mock_run_cli):
        """Test the main function."""
        mcp_fuzzer.__main__.main()
        mock_run_cli.assert_called_once()

    @patch.object(mcp_fuzzer.__main__, "run_cli")
    def test_run(self, mock_run_cli):
        """Test the run function."""
        mcp_fuzzer.__main__.run()
        mock_run_cli.assert_called_once()

    def test_main_import(self):
        """Test that the main module can be imported."""
        # This test ensures the module can be imported without issues
        import mcp_fuzzer.__main__

        self.assertTrue(hasattr(mcp_fuzzer.__main__, "main"))
        self.assertTrue(hasattr(mcp_fuzzer.__main__, "run"))

    @patch("mcp_fuzzer.__main__.run_cli")
    def test_main_module_execution(self, mock_run_cli):
        """Test that main() works when called directly (simulating __main__ branch)."""
        # The if __name__ == "__main__" branch calls main(), so we test that
        # main() works correctly, which is what the branch does
        # We patch run_cli at the import location in __main__ module
        import mcp_fuzzer.__main__ as main_module

        main_module.main()
        mock_run_cli.assert_called_once()


if __name__ == "__main__":
    unittest.main()
