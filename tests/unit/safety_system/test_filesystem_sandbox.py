#!/usr/bin/env python3
"""
Tests for Filesystem Sandbox functionality
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_fuzzer.safety_system.filesystem import (
    FilesystemSandbox,
    initialize_sandbox,
    get_sandbox,
    set_sandbox,
    cleanup_sandbox,
)


class TestFilesystemSandbox:
    """Test cases for FilesystemSandbox class."""

    def test_init_with_custom_path(self):
        """Test initialization with custom path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            assert sandbox.root_path == Path(temp_dir).resolve()
            assert sandbox.root_path.exists()

    def test_init_with_none_path(self):
        """Test initialization with None path uses default."""
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/tmp/test_home")
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.mkdir"):
                    sandbox = FilesystemSandbox(None)
                    expected_path = Path("/tmp/test_home/.mcp_fuzzer")
                    assert sandbox.root_path == expected_path.resolve()

    def test_init_creates_directory(self):
        """Test that initialization creates the directory if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_path = Path(temp_dir) / "new_sandbox"
            assert not test_path.exists()

            sandbox = FilesystemSandbox(str(test_path))
            assert test_path.exists()
            assert test_path.is_dir()

    def test_init_with_dangerous_path_raises_error(self):
        """Test that initialization with dangerous paths raises ValueError."""
        dangerous_paths = ["/etc/test", "/usr/bin/test", "/System/test"]

        for dangerous_path in dangerous_paths:
            with patch("pathlib.Path.mkdir"):
                with pytest.raises(ValueError, match="disallowed system location"):
                    FilesystemSandbox(dangerous_path)

    def test_init_allows_tmp_paths(self):
        """Test that initialization allows /tmp and /var/tmp paths."""
        safe_paths = ["/tmp/test", "/var/tmp/test"]

        for safe_path in safe_paths:
            # Mock the path to exist for testing
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.mkdir"):
                    sandbox = FilesystemSandbox(safe_path)
                    assert sandbox.root_path == Path(safe_path).resolve()

    def test_init_fallback_to_temp_on_error(self):
        """Test that initialization falls back to temp directory on error."""
        # Use a path that passes validation but fails during creation
        temp_dir = Path(tempfile.gettempdir())
        test_path = temp_dir / "test_fallback_path"

        with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
            sandbox = FilesystemSandbox(str(test_path))
            # Should fall back to a temporary directory
            assert "mcp_fuzzer_sandbox_" in str(sandbox.root_path)

    def test_is_path_safe_within_sandbox(self):
        """Test is_path_safe returns True for paths within sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Test various paths within the sandbox
            safe_paths = [
                str(sandbox.root_path / "file.txt"),
                str(sandbox.root_path / "subdir" / "file.txt"),
                str(sandbox.root_path),
            ]

            for path in safe_paths:
                assert sandbox.is_path_safe(path)

    def test_is_path_safe_outside_sandbox(self):
        """Test is_path_safe returns False for paths outside sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Test various paths outside the sandbox
            unsafe_paths = [
                "/etc/passwd",
                "/usr/bin/ls",
                str(Path(temp_dir).parent / "outside.txt"),
                "/tmp/other_file.txt",
            ]

            for path in unsafe_paths:
                assert not sandbox.is_path_safe(path)

    def test_is_path_safe_with_invalid_path(self):
        """Test is_path_safe handles invalid paths gracefully."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Test invalid paths
            invalid_paths = ["", None, "invalid://path", "\x00null"]

            for path in invalid_paths:
                if path is None:
                    continue  # Skip None as it's not a string
                assert not sandbox.is_path_safe(path)

    def test_sanitize_path_safe_path(self):
        """Test sanitize_path returns original path if safe."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            safe_path = str(sandbox.root_path / "safe_file.txt")

            result = sandbox.sanitize_path(safe_path)
            assert result == safe_path

    def test_sanitize_path_unsafe_path(self):
        """Test sanitize_path redirects unsafe paths to sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            unsafe_path = "/etc/passwd"

            result = sandbox.sanitize_path(unsafe_path)
            expected = str(sandbox.root_path / "passwd")
            assert result == expected

    def test_sanitize_path_empty_path(self):
        """Test sanitize_path handles empty path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            result = sandbox.sanitize_path("")
            expected = str(sandbox.root_path / "default")
            assert result == expected

    def test_sanitize_path_removes_dangerous_chars(self):
        """Test sanitize_path removes dangerous characters."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            dangerous_path = "/etc/passwd\x00<script>"

            result = sandbox.sanitize_path(dangerous_path)
            # Should only contain safe characters
            assert all(c.isalnum() or c in "._-" for c in Path(result).name)

    def test_create_safe_path(self):
        """Test create_safe_path creates safe filenames."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Test various filenames
            test_cases = [
                ("normal_file.txt", "normal_file.txt"),
                ("file with spaces.txt", "file_with_spaces.txt"),
                ("file/with/slashes.txt", "filewithslashes.txt"),
                ("", "default"),
                ("file\x00null.txt", "filenull.txt"),
            ]

            for input_name, expected_name in test_cases:
                result = sandbox.create_safe_path(input_name)
                expected_path = str(sandbox.root_path / expected_name)
                assert result == expected_path

    def test_get_sandbox_root(self):
        """Test get_sandbox_root returns the root directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            result = sandbox.get_sandbox_root()
            assert result == str(sandbox.root_path)

    def test_cleanup_temp_directory(self):
        """Test cleanup removes temporary directories."""
        with patch("tempfile.mkdtemp") as mock_mkdtemp:
            # Use a path that's actually under the system temp directory
            temp_root = Path(tempfile.gettempdir())
            temp_path = temp_root / "mcp_fuzzer_sandbox_test123"
            mock_mkdtemp.return_value = str(temp_path)

            # Use a path that passes validation but fails during creation
            temp_dir = Path(tempfile.gettempdir())
            test_path = temp_dir / "test_cleanup_path"

            # Mock mkdir to fail so it falls back to temp directory
            with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
                sandbox = FilesystemSandbox(str(test_path))

                with patch("shutil.rmtree") as mock_rmtree:
                    sandbox.cleanup()
                    mock_rmtree.assert_called_once_with(temp_path, ignore_errors=True)

    def test_cleanup_non_temp_directory(self):
        """Test cleanup does not remove non-temporary directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            with patch("shutil.rmtree") as mock_rmtree:
                sandbox.cleanup()
                mock_rmtree.assert_not_called()


class TestGlobalSandboxFunctions:
    """Test cases for global sandbox functions."""

    def test_initialize_sandbox_with_path(self):
        """Test initialize_sandbox with custom path."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = initialize_sandbox(temp_dir)
            assert isinstance(sandbox, FilesystemSandbox)
            assert sandbox.root_path == Path(temp_dir).resolve()

    def test_initialize_sandbox_with_none(self):
        """Test initialize_sandbox with None uses default."""
        with patch("pathlib.Path.home") as mock_home:
            mock_home.return_value = Path("/tmp/test_home")
            with patch("pathlib.Path.exists", return_value=True):
                with patch("pathlib.Path.mkdir"):
                    sandbox = initialize_sandbox(None)
                    expected_path = Path("/tmp/test_home/.mcp_fuzzer")
                    assert sandbox.root_path == expected_path.resolve()

    def test_get_sandbox_returns_current(self):
        """Test get_sandbox returns current sandbox instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = initialize_sandbox(temp_dir)
            current_sandbox = get_sandbox()
            assert current_sandbox is sandbox

    def test_get_sandbox_returns_none_when_not_initialized(self):
        """Test get_sandbox returns None when not initialized."""
        # Clean up any existing sandbox
        cleanup_sandbox()
        assert get_sandbox() is None

    def test_set_sandbox(self):
        """Test set_sandbox sets the global sandbox instance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)
            set_sandbox(sandbox)
            assert get_sandbox() is sandbox

    def test_cleanup_sandbox(self):
        """Test cleanup_sandbox cleans up the global sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = initialize_sandbox(temp_dir)
            assert get_sandbox() is not None

            cleanup_sandbox()
            assert get_sandbox() is None


class TestFilesystemSandboxIntegration:
    """Integration tests for filesystem sandbox."""

    def test_sandbox_prevents_outside_access(self):
        """Test that sandbox prevents access to files outside sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Create a test file outside the sandbox
            outside_file = Path(temp_dir).parent / "outside_file.txt"
            outside_file.write_text("secret content")

            try:
                # Try to access the file through sandbox
                safe_path = sandbox.sanitize_path(str(outside_file))

                # The path should be redirected to sandbox
                assert safe_path.startswith(str(sandbox.root_path))
                assert safe_path != str(outside_file)

                # The redirected file should not exist
                assert not Path(safe_path).exists()

            finally:
                # Clean up
                outside_file.unlink(missing_ok=True)

    def test_sandbox_allows_inside_access(self):
        """Test that sandbox allows access to files inside sandbox."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Create a test file inside the sandbox
            inside_file = sandbox.root_path / "inside_file.txt"
            inside_file.write_text("safe content")

            try:
                # Access the file through sandbox
                safe_path = sandbox.sanitize_path(str(inside_file))

                # The path should remain unchanged
                assert safe_path == str(inside_file)

                # The file should exist and be readable
                assert Path(safe_path).exists()
                assert Path(safe_path).read_text() == "safe content"

            finally:
                # Clean up
                inside_file.unlink(missing_ok=True)

    def test_sandbox_handles_complex_paths(self):
        """Test that sandbox handles complex path scenarios."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Test various complex path scenarios
            test_cases = [
                "../../../etc/passwd",
                "/etc/../etc/passwd",
                "file/with/../path/../../etc/passwd",
                "normal/file.txt",
                "file with spaces.txt",
                "file\x00with\x00nulls.txt",
            ]

            for test_path in test_cases:
                safe_path = sandbox.sanitize_path(test_path)

                # All paths should be within sandbox
                assert safe_path.startswith(str(sandbox.root_path))

                # Path should not contain dangerous characters
                path_name = Path(safe_path).name
                assert all(c.isalnum() or c in "._-" for c in path_name)

    def test_sandbox_permissions(self):
        """Test that sandbox directory has correct permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            sandbox = FilesystemSandbox(temp_dir)

            # Check that the directory has restrictive permissions
            stat_info = sandbox.root_path.stat()
            # On Unix systems, mode 0o700 means only owner can read/write/execute
            assert stat_info.st_mode & 0o777 == 0o700
