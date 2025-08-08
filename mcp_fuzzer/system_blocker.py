#!/usr/bin/env python3
"""
System-Level Command Blocker for MCP Fuzzer

This module creates fake system executables to intercept and block
browser/app opening commands at the OS level, even from other processes
like Node.js child_process.exec().
"""

import json
import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


class SystemCommandBlocker:
    """Blocks system commands by creating fake executables with higher PATH priority."""

    def __init__(self):
        self.temp_dir: Optional[Path] = None
        self.original_path: Optional[str] = None
        self.blocked_commands = [
            "xdg-open",  # Linux
            "open",  # macOS
            "start",  # Windows (cmd.exe builtin, but we can still block)
            "firefox",
            "chrome",
            "chromium",
            "google-chrome",
            "safari",
            "edge",
            "opera",
            "brave",
        ]
        self.created_files: List[Path] = []
        self.blocked_operations: List[Dict[str, str]] = []

    def start_blocking(self):
        """Start blocking dangerous system commands."""
        try:
            # Create temporary directory for fake executables
            self.temp_dir = Path(tempfile.mkdtemp(prefix="mcp_fuzzer_block_"))
            logging.info(f"🛡️ Created command blocking directory: {self.temp_dir}")

            # Create fake executables
            self._create_fake_executables()

            # Modify PATH to prioritize our fake executables
            self.original_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{self.temp_dir}:{self.original_path}"

            logging.info("🔒 System command blocking activated")
            logging.info(f"🚫 Blocked commands: {', '.join(self.blocked_commands)}")

        except Exception as e:
            logging.error(f"Failed to start system command blocking: {e}")
            self.stop_blocking()
            raise

    def stop_blocking(self):
        """Stop blocking and clean up."""
        try:
            # Restore original PATH
            if self.original_path is not None:
                os.environ["PATH"] = self.original_path
                self.original_path = None

            # Clean up fake executables
            for fake_exec in self.created_files:
                try:
                    if fake_exec.exists():
                        fake_exec.unlink()
                except Exception as e:
                    logging.warning(f"Failed to remove {fake_exec}: {e}")

            # Remove temp directory
            if self.temp_dir and self.temp_dir.exists():
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception as e:
                    logging.warning(f"Failed to remove temp dir {self.temp_dir}: {e}")

            self.created_files.clear()
            self.temp_dir = None

            logging.info("🔓 System command blocking stopped")

        except Exception as e:
            logging.error(f"Error during cleanup: {e}")

    def _create_fake_executables(self):
        """Create fake executable scripts that log and block commands."""
        if not self.temp_dir:
            raise RuntimeError("Temp directory not created")

        # Python script content for fake executables
        log_file = self.temp_dir / "blocked_operations.log"
        fake_script_content = f'''#!/usr/bin/env python3
import sys
import os
import json
from datetime import datetime

command_name = os.path.basename(sys.argv[0])
args = ' '.join(sys.argv[1:]) if len(sys.argv) > 1 else ''

# Log to stderr so it's visible
print(f"🚫 [FUZZER BLOCKED] {{command_name}} {{args}}", file=sys.stderr)
print(
    f"🛡️ Command '{{command_name}}' was blocked to prevent external app launch "
    f"during fuzzing",
    file=sys.stderr
)

# Log to shared file for summary reporting
try:
    log_entry = {{
        "timestamp": datetime.now().isoformat(),
        "command": command_name,
        "args": args,
        "full_command": f"{{command_name}} {{args}}".strip()
    }}

    with open("{log_file}", "a") as f:
        f.write(json.dumps(log_entry) + "\\n")
except Exception:
    pass  # Don't fail if logging fails

# Exit successfully to avoid breaking the calling process
sys.exit(0)
'''

        for command in self.blocked_commands:
            fake_exec_path = self.temp_dir / command

            try:
                # Write the fake executable script
                fake_exec_path.write_text(fake_script_content)

                # Make it executable
                fake_exec_path.chmod(
                    fake_exec_path.stat().st_mode
                    | stat.S_IEXEC
                    | stat.S_IXUSR
                    | stat.S_IXGRP
                    | stat.S_IXOTH
                )

                self.created_files.append(fake_exec_path)
                logging.debug(f"Created fake executable: {fake_exec_path}")

            except Exception as e:
                logging.error(f"Failed to create fake executable for {command}: {e}")

    def get_blocked_commands(self) -> List[str]:
        """Get list of commands that are being blocked."""
        return self.blocked_commands.copy()

    def get_blocked_operations(self) -> List[Dict[str, str]]:
        """Get list of operations that were actually blocked during fuzzing."""
        if not self.temp_dir:
            return []

        log_file = self.temp_dir / "blocked_operations.log"
        if not log_file.exists():
            return []

        operations = []
        try:
            with open(log_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            operations.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logging.warning(f"Failed to read blocked operations log: {e}")

        return operations

    def clear_blocked_operations(self):
        """Clear the log of blocked operations."""
        if self.temp_dir:
            log_file = self.temp_dir / "blocked_operations.log"
            if log_file.exists():
                try:
                    log_file.unlink()
                except Exception as e:
                    logging.warning(f"Failed to clear blocked operations log: {e}")

    def is_blocking_active(self) -> bool:
        """Check if blocking is currently active."""
        return self.temp_dir is not None and self.temp_dir.exists()


# Global blocker instance
_system_blocker = SystemCommandBlocker()


def start_system_blocking():
    """Start blocking dangerous system commands."""
    _system_blocker.start_blocking()


def stop_system_blocking():
    """Stop blocking dangerous system commands."""
    _system_blocker.stop_blocking()


def is_system_blocking_active() -> bool:
    """Check if system blocking is active."""
    return _system_blocker.is_blocking_active()


def get_blocked_commands() -> List[str]:
    """Get list of blocked commands."""
    return _system_blocker.get_blocked_commands()


def get_blocked_operations() -> List[Dict[str, str]]:
    """Get list of operations that were actually blocked during fuzzing."""
    return _system_blocker.get_blocked_operations()


def clear_blocked_operations():
    """Clear the log of blocked operations."""
    _system_blocker.clear_blocked_operations()


if __name__ == "__main__":
    # Test the system blocker
    print("Testing system command blocker...")

    start_system_blocking()

    try:
        import subprocess

        # Test that xdg-open is blocked
        print("Testing xdg-open blocking...")
        result = subprocess.run(
            ["xdg-open", "https://example.com"], capture_output=True, text=True
        )
        print(f"Return code: {result.returncode}")
        print(f"Stderr: {result.stderr}")

        # Test that firefox is blocked
        print("Testing firefox blocking...")
        result = subprocess.run(
            ["firefox", "https://google.com"], capture_output=True, text=True
        )
        print(f"Return code: {result.returncode}")
        print(f"Stderr: {result.stderr}")

    finally:
        stop_system_blocking()
        print("System blocker test completed!")
