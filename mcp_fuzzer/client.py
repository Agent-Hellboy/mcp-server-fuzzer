#!/usr/bin/env python3
"""
MCP Fuzzer Client supporting multiple transport protocols.
"""

import argparse
import asyncio
import logging
import traceback
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table

from .strategies import make_fuzz_strategy_from_jsonschema
from .transport import create_transport

logging.basicConfig(level=logging.INFO)


async def fuzz_tool(
    transport, tool: Dict[str, Any], runs: int = 10
) -> List[Dict[str, Any]]:
    """Fuzz a tool by calling it with random/edge-case arguments."""
    results = []
    schema = tool.get("inputSchema", {})
    strategy = make_fuzz_strategy_from_jsonschema(schema)

    for i in range(runs):
        args = strategy.example()
        try:
            logging.info(
                f"Fuzzing {tool['name']} (run {i + 1}/{runs}) with args: {args}"
            )
            result = await transport.call_tool(tool["name"], args)
            results.append({"args": args, "result": result})
        except Exception as e:
            logging.warning(f"Exception during fuzzing {tool['name']}: {e}")
            results.append(
                {"args": args, "exception": str(e), "traceback": traceback.format_exc()}
            )

    return results


async def main():
    parser = argparse.ArgumentParser(description="MCP Fuzzer Client")
    parser.add_argument(
        "--protocol",
        choices=["http", "sse", "stdio", "websocket"],
        default="http",
        help="Transport protocol to use (default: http)",
    )
    parser.add_argument(
        "--endpoint",
        required=True,
        help="Server endpoint (URL for http/sse/websocket, command for stdio)",
    )
    parser.add_argument(
        "--runs", type=int, default=10, help="Number of fuzzing runs per tool"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Request timeout in seconds (default: 30.0)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create transport
    try:
        transport = create_transport(
            protocol=args.protocol, endpoint=args.endpoint, timeout=args.timeout
        )
        logging.info(f"Created {args.protocol} transport for endpoint: {args.endpoint}")
    except Exception as e:
        logging.error(f"Failed to create transport: {e}")
        return

    # Get tools from server
    try:
        tools = await transport.get_tools()
        if not tools:
            logging.warning("Server returned an empty list of tools. Exiting.")
            return
        logging.info(f"Found {len(tools)} tools to fuzz")
    except Exception as e:
        logging.error(f"Failed to get tools from server: {e}")
        return

    # Fuzz each tool
    summary = {}
    for tool in tools:
        tool_name = tool.get("name", "unknown")
        logging.info(f"Starting to fuzz tool: {tool_name}")

        try:
            results = await fuzz_tool(transport, tool, args.runs)
            exceptions = [r for r in results if "exception" in r]

            summary[tool_name] = {
                "total_runs": args.runs,
                "exceptions": len(exceptions),
                "success_rate": ((args.runs - len(exceptions)) / args.runs) * 100,
                "example_exception": exceptions[0] if exceptions else None,
            }

            logging.info(
                f"Completed fuzzing {tool_name}: {len(exceptions)} exceptions out of {args.runs} runs"
            )

        except Exception as e:
            logging.error(f"Failed to fuzz tool {tool_name}: {e}")
            summary[tool_name] = {"error": str(e)}

    # Print summary
    console = Console()
    table = Table(title=f"Fuzzing Summary - {args.protocol.upper()} Protocol")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Total Runs", justify="right")
    table.add_column("Exceptions", justify="right")
    table.add_column("Success Rate", justify="right")
    table.add_column("Example Exception", style="red")
    table.add_column("Error", style="magenta")

    for tool, result in summary.items():
        error = result.get("error", "")
        total_runs = str(result.get("total_runs", ""))
        exceptions = str(result.get("exceptions", ""))
        success_rate = (
            f"{result.get('success_rate', 0):.1f}%" if "success_rate" in result else ""
        )
        example_exception = ""
        if result.get("example_exception"):
            ex = result["example_exception"]
            example_exception = (
                ex.get("exception", "")[:50] + "..."
                if len(ex.get("exception", "")) > 50
                else ex.get("exception", "")
            )

        table.add_row(
            tool, total_runs, exceptions, success_rate, example_exception, error
        )

    console.print(table)

    # Print overall statistics
    total_tools = len(summary)
    tools_with_errors = len([r for r in summary.values() if "error" in r])
    tools_with_exceptions = len(
        [r for r in summary.values() if r.get("exceptions", 0) > 0]
    )

    console.print("\n[bold]Overall Statistics:[/bold]")
    console.print(f"Total tools tested: {total_tools}")
    console.print(f"Tools with errors: {tools_with_errors}")
    console.print(f"Tools with exceptions: {tools_with_exceptions}")
    console.print(f"Protocol used: {args.protocol.upper()}")
    console.print(f"Endpoint: {args.endpoint}")


if __name__ == "__main__":
    asyncio.run(main())
