#!/usr/bin/env python3
"""Async loop management and signal handling for CLI execution."""

import asyncio
import signal
import sys
from typing import Any, Optional


class LoopManager:
    """Manages async event loops and signal handling for CLI operations."""

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._signal_handlers_installed = False
        self._shutdown_requested = False

    def setup_signal_handlers(self) -> None:
        """Set up signal handlers for graceful shutdown."""
        if self._signal_handlers_installed:
            return

        def signal_handler(signum, frame):
            """Handle shutdown signals."""
            print(f"\nReceived signal {signum}, initiating graceful shutdown...")
            self._shutdown_requested = True
            if self._loop and not self._loop.is_closed():
                self._loop.stop()

        # Handle common termination signals
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Handle SIGHUP on Unix-like systems
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, signal_handler)

        self._signal_handlers_installed = True

    def run_async(self, coro) -> Any:
        """Run an async coroutine with proper loop management."""
        try:
            # Try to get the current running loop first
            try:
                loop = asyncio.get_running_loop()
                # If we're already in a running loop, create a task
                return loop.create_task(coro)
            except RuntimeError:
                # No running loop, create a new one
                pass

            # Create new event loop
            if sys.platform == 'win32':
                # Use SelectorEventLoop on Windows for better compatibility
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            try:
                self.setup_signal_handlers()
                return self._loop.run_until_complete(coro)
            finally:
                try:
                    # Cancel all pending tasks
                    pending = [
                        task for task in asyncio.all_tasks(self._loop)
                        if not task.done()
                    ]
                    for task in pending:
                        task.cancel()

                    # Wait for tasks to cancel
                    if pending:
                        self._loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )

                    # Close the loop
                    self._loop.close()
                except Exception:
                    pass  # Ignore cleanup errors

        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            sys.exit(130)
        except Exception as e:
            print(f"Error during async execution: {e}")
            raise

    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self._shutdown_requested

    def reset_shutdown_flag(self) -> None:
        """Reset the shutdown flag."""
        self._shutdown_requested = False
