#!/usr/bin/env python3
"""
Filesystem Sandbox for MCP Fuzzer

This module implements filesystem sandboxing to confine file operations
to a specified directory, preventing accidental modification of system files.
"""

import logging
import os
import tempfile
from pathlib import Path


class FilesystemSandbox:
    """Filesystem sandbox that restricts file operations to a safe directory."""

    def __init__(self, root_path: str | None = None):
        """Initialize the filesystem sandbox.

        Args:
            root_path: Path to the sandbox directory. If None, uses default.
        """
        if root_path is None:
            # Use default sandbox directory
            default_path = Path.home() / ".mcp_fuzzer"
            root_path = str(default_path)

        self.root_path = Path(root_path).resolve()
        self._is_temp: bool = False
        self.ensure_safe_directory()
        logging.info("Filesystem sandbox initialized at: %s", self.root_path)

    def ensure_safe_directory(self):
        """Ensure the sandbox directory exists and is safe."""
        try:
            # Ensure directory is not in dangerous locations.
            # Allow under HOME and temp directories; reject critical system roots.
            temp_root = Path(tempfile.gettempdir()).resolve()
            home_root = Path.home().resolve()
            # Also allow /tmp and /var/tmp specifically (resolve to handle symlinks)
            tmp_paths = [Path("/tmp").resolve(), Path("/var/tmp").resolve()]

            disallowed = [
                Path("/"),
                Path("/etc"),
                Path("/usr"),
                Path("/bin"),
                Path("/sbin"),
                Path("/System"),
                Path("/dev"),
                Path("/proc"),
            ]

            # Check if path is under allowed locations
            is_under_temp = self.root_path.is_relative_to(temp_root)
            is_under_home = self.root_path.is_relative_to(home_root)
            is_under_tmp = any(self.root_path.is_relative_to(tmp) for tmp in tmp_paths)

            # If not under any allowed location, check if it's in a disallowed location
            if not (is_under_temp or is_under_home or is_under_tmp):
                for disallowed_path in disallowed:
                    if (
                        self.root_path == disallowed_path
                        or self.root_path.is_relative_to(disallowed_path)
                    ):
                        raise ValueError(
                            f"Sandbox path {self.root_path} is in a "
                            f"disallowed system location"
                        )
            # Require the sandbox to live under HOME, system temp, or /tmp
            # (not the root of any)
            if not (
                self.root_path.is_relative_to(home_root)
                or self.root_path.is_relative_to(temp_root)
                or is_under_tmp
            ):
                raise ValueError(
                    f"Sandbox path {self.root_path} must be under HOME, "
                    f"temp directory, or /tmp"
                )
            if self.root_path in (home_root, temp_root) or self.root_path in tmp_paths:
                raise ValueError(
                    "Refusing to use HOME, TMP, or /tmp root as the sandbox directory"
                )

            # Create the directory if it doesn't exist
            self.root_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Harden permissions against umask
            try:
                os.chmod(self.root_path, 0o700)
            except OSError:
                warning_msg = "Failed to enforce 0700 permissions on %s"
                logging.warning(warning_msg, self.root_path)

        except ValueError:
            # Re-raise ValueError for dangerous paths
            raise
        except Exception as e:
            logging.error("Failed to create safe directory %s: %s", self.root_path, e)
            # Fall back to a temporary directory
            self.root_path = Path(tempfile.mkdtemp(prefix="mcp_fuzzer_sandbox_"))
            # Enforce 0700 on fallback as well
            try:
                os.chmod(self.root_path, 0o700)
            except OSError:
                warning_msg = "Failed to enforce 0700 permissions on %s"
                logging.warning(warning_msg, self.root_path)
            self._is_temp = True
            logging.info("Using temporary sandbox directory: %s", self.root_path)

    def is_path_safe(self, path: str) -> bool:
        """Check if a path is within the safe sandbox.

        Args:
            path: The path to check

        Returns:
            True if the path is within the sandbox, False otherwise
        """
        try:
            abs_path = Path(path).resolve()
            return abs_path.is_relative_to(self.root_path)
        except (OSError, ValueError, RuntimeError):
            return False

    def sanitize_path(self, path: str) -> str:
        """Sanitize a path to ensure it's within the sandbox.

        Args:
            path: The path to sanitize

        Returns:
            A safe path within the sandbox
        """
        if not path:
            return str(self.root_path / "default")

        try:
            abs_path = Path(path).resolve()
            if abs_path.is_relative_to(self.root_path):
                return str(abs_path)
        except (OSError, ValueError, RuntimeError):
            pass

        # If path is not safe, create a safe version under the sandbox root.
        base = os.path.basename(path) or "default"
        safe_name = "".join(c for c in base if c.isalnum() or c in "._-") or "default"
        candidate = self.root_path / safe_name
        try:
            # Prevent returning a symlink path
            if candidate.exists() and candidate.is_symlink():
                safe_name = f"{safe_name}.safe"
                candidate = self.root_path / safe_name
        except OSError:
            pass
        return str(candidate)

    def create_safe_path(self, filename: str) -> str:
        """Create a safe path for a filename within the sandbox.

        Args:
            filename: The filename to create a safe path for

        Returns:
            A safe path within the sandbox
        """
        if not filename:
            filename = "default"

        # Replace spaces with underscores and remove dangerous characters
        safe_filename = filename.replace(" ", "_")
        safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in "._-")
        if not safe_filename:
            safe_filename = "default"

        return str(self.root_path / safe_filename)

    def get_sandbox_root(self) -> str:
        """Get the sandbox root directory path.

        Returns:
            The sandbox root directory path
        """
        return str(self.root_path)

    def cleanup(self):
        """Clean up the sandbox directory if it's temporary."""
        try:
            temp_root = Path(tempfile.gettempdir()).resolve()
            if (
                getattr(self, "_is_temp", False)
                and self.root_path.resolve().is_relative_to(temp_root)
                and self.root_path.name.startswith("mcp_fuzzer_sandbox_")
            ):
                import shutil

                shutil.rmtree(self.root_path, ignore_errors=True)
                logging.info("Cleaned up temporary sandbox: %s", self.root_path)
        except Exception as e:
            logging.warning("Failed to cleanup sandbox %s: %s", self.root_path, e)


# Global sandbox instance
_sandbox: FilesystemSandbox | None = None


def get_sandbox() -> FilesystemSandbox | None:
    """Get the global filesystem sandbox instance.

    Returns:
        The global sandbox instance or None if not initialized
    """
    return _sandbox


def set_sandbox(sandbox: FilesystemSandbox) -> None:
    """Set the global filesystem sandbox instance.

    Args:
        sandbox: The sandbox instance to set as global
    """
    global _sandbox
    _sandbox = sandbox


def initialize_sandbox(root_path: str | None = None) -> FilesystemSandbox:
    """Initialize the global filesystem sandbox.

    Args:
        root_path: Path to the sandbox directory

    Returns:
        The initialized sandbox instance
    """
    global _sandbox
    _sandbox = FilesystemSandbox(root_path)
    return _sandbox


def cleanup_sandbox() -> None:
    """Clean up the global sandbox."""
    global _sandbox
    if _sandbox:
        _sandbox.cleanup()
        _sandbox = None
