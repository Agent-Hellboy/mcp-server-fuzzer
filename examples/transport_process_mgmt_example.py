#!/usr/bin/env python3
"""
Example demonstrating Process Management integration in Transport layer.

This script shows how the new Process Management system is integrated
into the transport layer for better process control and monitoring.
"""

import asyncio
import logging
import time
import os
from mcp_fuzzer.transport import create_transport, HTTPTransport, StdioTransport
from mcp_fuzzer.process_mgmt import ProcessConfig

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def create_test_server_script():
    """Create a simple test server script."""
    script_content = '''#!/usr/bin/env python3
import json
import sys
import time

def main():
    print("Test server started", file=sys.stderr)

    while True:
        try:
            # Read JSON-RPC request
            line = input()
            request = json.loads(line)

            # Simulate some processing time
            time.sleep(0.1)

            # Send response
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {"status": "success", "method": request.get("method")}
            }
            print(json.dumps(response))

        except EOFError:
            break
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": request.get("id") if 'request' in locals() else None,
                "error": {"code": -1, "message": str(e)}
            }
            print(json.dumps(error_response))

    print("Test server stopped", file=sys.stderr)

if __name__ == "__main__":
    main()
'''

    script_path = "/tmp/test_server.py"
    with open(script_path, 'w') as f:
        f.write(script_content)

    # Make it executable
    os.chmod(script_path, 0o755)
    return script_path

async def test_stdio_transport():
    """Test stdio transport with process management."""
    print("=== Testing Stdio Transport with Process Management ===")

    # Create test server script
    server_script = create_test_server_script()

    try:
        # Create stdio transport
        transport = StdioTransport(
            command=f"python3 {server_script}",
            timeout=10.0
        )

        print("Stdio transport created")

        # Get initial process stats
        stats = transport.get_process_stats()
        print(f"Initial process stats: {stats}")

        # Send a request (this will start the process)
        print("Sending request to start process...")
        response = await transport.send_request("tools/list")
        print(f"Response received: {response}")

        # Get updated process stats
        stats = transport.get_process_stats()
        print(f"Updated process stats: {stats}")

        # Send another request
        print("Sending another request...")
        response = await transport.send_request("tools/call", {"name": "test_tool"})
        print(f"Response received: {response}")

        # Test timeout signal capability
        print("Testing timeout signal capability...")
        success = transport.send_timeout_signal("timeout")
        print(f"Timeout signal sent: {success}")

        # Wait a bit for graceful shutdown
        await asyncio.sleep(2)

        # Check if process is still running
        stats = transport.get_process_stats()
        print(f"Process stats after timeout signal: {stats}")

        # Close transport
        await transport.close()
        print("Stdio transport closed")

    finally:
        # Clean up test script
        try:
            os.unlink(server_script)
        except:
            pass

async def test_http_transport():
    """Test HTTP transport with process management."""
    print("\n=== Testing HTTP Transport with Process Management ===")

    # Create HTTP transport
    transport = HTTPTransport(
        url="http://httpbin.org/json",
        timeout=10.0
    )

    print("HTTP transport created")

    # Get process stats
    stats = transport.get_process_stats()
    print(f"Process stats: {stats}")

    # Send a request
    print("Sending request to httpbin...")
    try:
        response = await transport.send_request("GET")
        print(f"Response received: {response}")
    except Exception as e:
        print(f"Request failed (expected for httpbin): {e}")

    # Test timeout signal capability
    print("Testing timeout signal capability...")
    results = transport.send_timeout_signal_to_all("timeout")
    print(f"Timeout signals sent: {results}")

    # Close transport
    await transport.close()
    print("HTTP transport closed")

async def test_transport_factory():
    """Test transport factory with process management."""
    print("\n=== Testing Transport Factory with Process Management ===")

    # Create test server script
    server_script = create_test_server_script()

    try:
        # Create stdio transport through factory
        transport = create_transport(
            protocol="stdio",
            endpoint=f"python3 {server_script}",
            timeout=10.0
        )

        print("Transport created through factory")

        # Get process stats
        if hasattr(transport, 'get_process_stats'):
            stats = transport.get_process_stats()
            print(f"Process stats: {stats}")

        # Send a request
        print("Sending request...")
        response = await transport.send_request("tools/list")
        print(f"Response received: {response}")

        # Close transport
        if hasattr(transport, 'close'):
            await transport.close()
            print("Transport closed")

    finally:
        # Clean up test script
        try:
            os.unlink(server_script)
        except:
            pass

async def test_process_monitoring():
    """Test process monitoring capabilities."""
    print("\n=== Testing Process Monitoring Capabilities ===")

    # Create test server script
    server_script = create_test_server_script()

    try:
        # Create stdio transport
        transport = StdioTransport(
            command=f"python3 {server_script}",
            timeout=5.0  # Short timeout for testing
        )

        print("Transport created with short timeout")

        # Send initial request
        print("Sending initial request...")
        response = await transport.send_request("tools/list")
        print(f"Response received: {response}")

        # Let the process run for a bit
        print("Letting process run for 3 seconds...")
        await asyncio.sleep(3)

        # Get process stats
        stats = transport.get_process_stats()
        print(f"Process stats after 3 seconds: {stats}")

        # Send timeout signal to test graceful shutdown
        print("Sending timeout signal for graceful shutdown...")
        success = transport.send_timeout_signal("timeout")
        print(f"Timeout signal sent: {success}")

        # Wait for shutdown
        await asyncio.sleep(2)

        # Get final stats
        final_stats = transport.get_process_stats()
        print(f"Final process stats: {final_stats}")

        # Close transport
        await transport.close()
        print("Transport closed")

    finally:
        # Clean up test script
        try:
            os.unlink(server_script)
        except:
            pass

async def main():
    """Run all transport process management tests."""
    print("Transport Process Management Integration Tests")
    print("=" * 60)

    try:
        # Test stdio transport
        await test_stdio_transport()

        # Test HTTP transport
        await test_http_transport()

        # Test transport factory
        await test_transport_factory()

        # Test process monitoring
        await test_process_monitoring()

        print("\n✅ All transport process management tests completed successfully!")

    except Exception as e:
        print(f"\n❌ Error running transport tests: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
