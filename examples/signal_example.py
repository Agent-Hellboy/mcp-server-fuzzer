#!/usr/bin/env python3
"""
Example demonstrating timeout signal handling in the Process Management system.

This script shows how to:
1. Send timeout signals to processes
2. Handle graceful shutdown vs force kill
3. Use different signal types (SIGTERM, SIGKILL, SIGINT)
"""

import asyncio
import logging
import time
import os
import signal
from mcp_fuzzer.process_mgmt import (
    ProcessManager,
    ProcessConfig,
    WatchdogConfig,
    AsyncProcessWrapper
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def create_hanging_script():
    """Create a script that hangs and can be interrupted."""
    script_content = '''#!/usr/bin/env python3
import signal
import time
import sys

def signal_handler(signum, frame):
    print(f"Received signal {signum}")
    if signum == signal.SIGTERM:
        print("Graceful shutdown requested")
        sys.exit(0)
    elif signum == signal.SIGINT:
        print("Interrupt received")
        sys.exit(1)
    else:
        print("Unknown signal, exiting")
        sys.exit(1)

# Set up signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

print("Hanging script started - will hang for 30 seconds or until interrupted")
print("PID:", os.getpid())

# Hang for 30 seconds
for i in range(30):
    time.sleep(1)
    print(f"Hanging... {i+1}/30")

print("Hanging script completed normally")
sys.exit(0)
'''

    script_path = "/tmp/hanging_script.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable
    os.chmod(script_path, 0o755)
    return script_path

def sync_signal_example():
    """Demonstrate synchronous signal handling."""
    print("=== Synchronous Signal Handling Example ===")

    # Create watchdog with aggressive settings
    watchdog_config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=10.0,    # Process timeout after 10 seconds
        extra_buffer=2.0,        # Extra 2 seconds before killing
        max_hang_time=15.0,      # Force kill after 15 seconds
        auto_kill=True,          # Automatically kill hanging processes
        log_level="INFO"
    )

    manager = ProcessManager(watchdog_config)

    try:
        # Create hanging script
        hanging_script = create_hanging_script()

        # Start the hanging script
        config = ProcessConfig(
            command=["python3", hanging_script],
            name="hanging_script",
            timeout=10.0
        )

        print("Starting hanging script...")
        process = manager.start_process(config)
        print(f"Process started with PID: {process.pid}")

        # Let it run for a bit
        print("Letting process run for 5 seconds...")
        time.sleep(5)

        # Send timeout signal (SIGTERM)
        print("Sending timeout signal (SIGTERM)...")
        success = manager.send_timeout_signal(process.pid, "timeout")
        print(f"Timeout signal sent: {success}")

        # Wait a bit more to see if it terminates gracefully
        print("Waiting for graceful termination...")
        time.sleep(3)

        # Check status
        status = manager.get_process_status(process.pid)
        print(f"Process status: {status}")

        # If still running, send force signal
        if status and status.get('status') == 'running':
            print("Process still running, sending force signal (SIGKILL)...")
            success = manager.send_timeout_signal(process.pid, "force")
            print(f"Force signal sent: {success}")

            # Wait for final status
            time.sleep(2)
            final_status = manager.get_process_status(process.pid)
            print(f"Final process status: {final_status}")

        # Get final statistics
        stats = manager.get_stats()
        print(f"Process manager stats: {stats}")

        # Clean up script
        try:
            os.unlink(hanging_script)
        except:
            pass

    finally:
        manager.shutdown()
        print("Process manager shutdown complete")


async def async_signal_example():
    """Demonstrate asynchronous signal handling."""
    print("\n=== Asynchronous Signal Handling Example ===")

    wrapper = AsyncProcessWrapper()

    try:
        # Create hanging script
        hanging_script = create_hanging_script()

        # Start the hanging script
        config = ProcessConfig(
            command=["python3", hanging_script],
            name="async_hanging_script",
            timeout=10.0
        )

        print("Starting hanging script asynchronously...")
        process = await wrapper.start_process(config)
        print(f"Process started with PID: {process.pid}")

        # Let it run for a bit
        print("Letting process run for 5 seconds...")
        await asyncio.sleep(5)

        # Send interrupt signal (SIGINT)
        print("Sending interrupt signal (SIGINT)...")
        success = await wrapper.send_timeout_signal(process.pid, "interrupt")
        print(f"Interrupt signal sent: {success}")

        # Wait for completion
        print("Waiting for process to complete...")
        exit_code = await wrapper.wait_for_process(process.pid, timeout=10.0)
        print(f"Process completed with exit code: {exit_code}")

        # Get final statistics
        stats = await wrapper.get_stats()
        print(f"Final stats: {stats}")

        # Clean up script
        try:
            os.unlink(hanging_script)
        except:
            pass

    finally:
        await wrapper.shutdown()
        print("Async process wrapper shutdown complete")


def signal_all_example():
    """Demonstrate sending signals to all processes."""
    print("\n=== Signal All Processes Example ===")

    manager = ProcessManager()

    try:
        # Create multiple hanging scripts
        scripts = []
        processes = []

        for i in range(3):
            script = create_hanging_script()
            scripts.append(script)

            config = ProcessConfig(
                command=["python3", script],
                name=f"hanging_script_{i}",
                timeout=10.0
            )

            process = manager.start_process(config)
            processes.append(process)
            print(f"Started process {i+1} with PID: {process.pid}")

        # Let them run for a bit
        print("Letting all processes run for 5 seconds...")
        time.sleep(5)

        # Send timeout signal to all processes
        print("Sending timeout signal to all processes...")
        results = manager.send_timeout_signal_to_all("timeout")
        print(f"Signal results: {results}")

        # Wait for all to complete
        print("Waiting for all processes to complete...")
        for i, process in enumerate(processes):
            exit_code = manager.wait_for_process(process.pid, timeout=10.0)
            print(f"Process {i+1} completed with exit code: {exit_code}")

        # Get final statistics
        stats = manager.get_stats()
        print(f"Final stats: {stats}")

        # Clean up scripts
        for script in scripts:
            try:
                os.unlink(script)
            except:
                pass

    finally:
        manager.shutdown()
        print("Process manager shutdown complete")


async def main():
    """Run all signal examples."""
    print("Process Management Signal Handling Examples")
    print("=" * 60)

    try:
        # Run synchronous signal example
        sync_signal_example()

        # Run async signal example
        await async_signal_example()

        # Run signal all example
        signal_all_example()

        print("\n✅ All signal examples completed successfully!")

    except Exception as e:
        print(f"\n❌ Error running signal examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
