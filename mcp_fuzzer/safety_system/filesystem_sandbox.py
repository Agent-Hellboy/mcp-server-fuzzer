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
from typing import Optional


class FilesystemSandbox:
    """Filesystem sandbox that restricts file operations to a safe directory."""

    def __init__(self, root_path: Optional[str] = None):
        """Initialize the filesystem sandbox.
        
        Args:
            root_path: Path to the sandbox directory. If None, uses default.
        """
        if root_path is None:
            # Use default sandbox directory
            default_path = Path.home() / ".mcp_fuzzer"
            root_path = str(default_path)
        
        self.root_path = Path(root_path).resolve()
        self.ensure_safe_directory()
        logging.info(f"Filesystem sandbox initialized at: {self.root_path}")

    def ensure_safe_directory(self):
        """Ensure the sandbox directory exists and is safe."""
        try:
            # Create the directory if it doesn't exist
            self.root_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Ensure directory is not in dangerous locations
            dangerous_paths = [
                "/etc", "/usr", "/bin", "/sbin", "/System", "/home",
                "/private/etc", "/private/usr", "/private/bin", "/private/sbin"
            ]
            for dangerous in dangerous_paths:
                dangerous_path = Path(dangerous)
                try:
                    # Check both the original path and resolved path
                    if (self.root_path.is_relative_to(dangerous_path) and 
                        self.root_path != dangerous_path):
                        # Allow /tmp and /var/tmp as they are safe temporary locations
                        if (dangerous_path.name in ["tmp", "var"] and 
                            "tmp" in str(self.root_path)):
                            continue
                        # Allow /tmp specifically
                        if str(self.root_path).startswith("/tmp/"):
                            continue
                        raise ValueError(
                            f"Sandbox path {self.root_path} is in dangerous "
                            f"location: {dangerous}"
                        )
                    # Also check if the path starts with the dangerous path
                    if str(self.root_path).startswith(dangerous + "/"):
                        raise ValueError(
                            f"Sandbox path {self.root_path} is in dangerous "
                            f"location: {dangerous}"
                        )
                except OSError:
                    # If we can't resolve the path, it's probably safe
                    pass
                    
        except ValueError:
            # Re-raise ValueError for dangerous paths
            raise
        except Exception as e:
            logging.error(f"Failed to create safe directory {self.root_path}: {e}")
            # Fall back to a temporary directory
            self.root_path = Path(tempfile.mkdtemp(prefix="mcp_fuzzer_sandbox_"))
            logging.info(f"Using temporary sandbox directory: {self.root_path}")

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
            
        # If path is not safe, create a safe version
        safe_name = os.path.basename(path) or "default"
        # Remove dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")
        if not safe_name:
            safe_name = "default"
            
        return str(self.root_path / safe_name)

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
            if "mcp_fuzzer_sandbox_" in str(self.root_path):
                import shutil
                shutil.rmtree(self.root_path, ignore_errors=True)
                logging.info(f"Cleaned up temporary sandbox: {self.root_path}")
        except Exception as e:
            logging.warning(f"Failed to cleanup sandbox {self.root_path}: {e}")


# Global sandbox instance
_sandbox: Optional[FilesystemSandbox] = None


def get_sandbox() -> Optional[FilesystemSandbox]:
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


def initialize_sandbox(root_path: Optional[str] = None) -> FilesystemSandbox:
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
