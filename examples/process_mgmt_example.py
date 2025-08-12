#!/usr/bin/env python3
"""
Example usage of the Process Management system.

This script demonstrates how to use the ProcessManager and AsyncProcessWrapper
to manage processes with automatic watchdog monitoring.
"""

import asyncio
import logging
import time
import sys
import os
from mcp_fuzzer.process_mgmt import (
    ProcessManager,
    ProcessConfig,
    WatchdogConfig,
    AsyncProcessWrapper,
    AsyncProcessGroup
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def create_test_script():
    """Create a simple test script that exits quickly."""
    script_content = '''#!/usr/bin/env python3
import time
import sys
print("Test script started")
time.sleep(2)  # Wait 2 seconds
print("Test script completed")
sys.exit(0)
'''

    script_path = "/tmp/test_script.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable
    os.chmod(script_path, 0o755)
    return script_path

def sync_example():
    """Demonstrate synchronous process management."""
    print("=== Synchronous Process Management Example ===")

    # Create a custom watchdog configuration
    watchdog_config = WatchdogConfig(
        check_interval=0.5,      # Check every 0.5 seconds
        process_timeout=10.0,    # Process timeout after 10 seconds
        extra_buffer=2.0,        # Extra 2 seconds before killing
        max_hang_time=20.0,      # Force kill after 20 seconds
        auto_kill=True,          # Automatically kill hanging processes
        log_level="INFO"
    )

    # Create process manager with custom watchdog config
    manager = ProcessManager(watchdog_config)

    try:
        # Create a test script
        test_script = create_test_script()

        # Start the test script
        config = ProcessConfig(
            command=["python3", test_script],
            name="test_script",
            timeout=10.0
        )

        print("Starting test script...")
        process = manager.start_process(config)
        print(f"Process started with PID: {process.pid}")

        # Wait for process to complete
        print("Waiting for process to complete...")
        exit_code = manager.wait_for_process(process.pid, timeout=10.0)
        print(f"Process completed with exit code: {exit_code}")

        # Get statistics
        stats = manager.get_stats()
        print(f"Process manager stats: {stats}")

        # Clean up test script
        try:
            os.unlink(test_script)
        except:
            pass

    finally:
        # Cleanup
        manager.shutdown()
        print("Process manager shutdown complete")


async def async_example():
    """Demonstrate asynchronous process management."""
    print("\n=== Asynchronous Process Management Example ===")

    # Create async process wrapper
    wrapper = AsyncProcessWrapper()

    try:
        # Create test scripts
        script1 = create_test_script()
        script2 = create_test_script()

        # Start multiple processes
        processes = {}

        # Process 1: Run test script
        config1 = ProcessConfig(
            command=["python3", script1],
            name="async_test_1",
            timeout=10.0
        )
        processes["test1"] = await wrapper.start_process(config1)

        # Process 2: Run another test script
        config2 = ProcessConfig(
            command=["python3", script2],
            name="async_test_2",
            timeout=10.0
        )
        processes["test2"] = await wrapper.start_process(config2)

        print(f"Started {len(processes)} processes")

        # Wait for all processes to complete
        print("Waiting for all processes to complete...")
        for name, process in processes.items():
            if process:
                exit_code = await wrapper.wait_for_process(process.pid)
                print(f"Process {name} completed with exit code: {exit_code}")

        # Get final statistics
        stats = await wrapper.get_stats()
        print(f"Final stats: {stats}")

        # Clean up test scripts
        for script in [script1, script2]:
            try:
                os.unlink(script)
            except:
                pass

    finally:
        # Cleanup
        await wrapper.shutdown()
        print("Async process wrapper shutdown complete")


async def process_group_example():
    """Demonstrate process group management."""
    print("\n=== Process Group Management Example ===")

    # Create process group
    group = AsyncProcessGroup()

    try:
        # Create test scripts
        scripts = []
        for i in range(3):
            script = create_test_script()
            scripts.append(script)

        # Add multiple process configurations
        await group.add_process("test1", ProcessConfig(
            command=["python3", scripts[0]],
            name="group_test_1"
        ))

        await group.add_process("test2", ProcessConfig(
            command=["python3", scripts[1]],
            name="group_test_2"
        ))

        await group.add_process("test3", ProcessConfig(
            command=["python3", scripts[2]],
            name="group_test_3"
        ))

        # Start all processes
        print("Starting all processes in group...")
        started = await group.start_all()
        print(f"Started {len(started)} processes")

        # Wait for all to complete
        print("Waiting for all processes to complete...")
        results = await group.wait_for_all()
        print(f"All processes completed: {results}")

        # Get group status
        status = await group.get_group_status()
        print(f"Group status: {status}")

        # Clean up test scripts
        for script in scripts:
            try:
                os.unlink(script)
            except:
                pass

    finally:
        # Cleanup
        await group.shutdown()
        print("Process group shutdown complete")


def hanging_process_example():
    """Demonstrate watchdog behavior with a hanging process."""
    print("\n=== Hanging Process Example ===")

    # Create a script that will hang
    hanging_script_content = '''#!/usr/bin/env python3
import time
print("Hanging script started - will hang for 10 seconds")
time.sleep(10)  # Hang for 10 seconds
print("Hanging script completed")
'''

    hanging_script = "/tmp/hanging_script.py"
    with open(hanging_script, 'w') as f:
        f.write(hanging_script_content)
    os.chmod(hanging_script, 0o755)

    # Create watchdog with aggressive settings
    watchdog_config = WatchdogConfig(
        check_interval=1.0,
        process_timeout=3.0,     # Very short timeout for demo
        extra_buffer=1.0,
        max_hang_time=8.0,
        auto_kill=True,
        log_level="INFO"
    )

    manager = ProcessManager(watchdog_config)

    try:
        # Start the hanging script
        config = ProcessConfig(
            command=["python3", hanging_script],
            name="hanging_script",
            timeout=3.0
        )

        print("Starting hanging script (will be killed by watchdog)...")
        process = manager.start_process(config)
        print(f"Process started with PID: {process.pid}")

        # Let it run for a bit to see watchdog in action
        print("Letting process run for 8 seconds to see watchdog behavior...")
        time.sleep(8)

        # Check status
        status = manager.get_process_status(process.pid)
        print(f"Process status: {status}")

        # Get stats
        stats = manager.get_stats()
        print(f"Process manager stats: {stats}")

        # Clean up hanging script
        try:
            os.unlink(hanging_script)
        except:
            pass

    finally:
        # Cleanup
        manager.shutdown()
        print("Process manager shutdown complete")


async def main():
    """Run all examples."""
    print("Process Management System Examples")
    print("=" * 50)

    try:
        # Run synchronous example
        sync_example()

        # Run async examples
        await async_example()
        await process_group_example()

        # Run hanging process example
        hanging_process_example()

        print("\n✅ All examples completed successfully!")

    except Exception as e:
        print(f"\n❌ Error running examples: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
